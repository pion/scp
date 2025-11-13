// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package generate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/pion/scp/internal/scp"
	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

const (
	rootModulePath      = "generated"
	apiPackageName      = "api"
	harnessPackageName  = "harness"
	internalDepsDirName = "internaldeps"
	wrappersDirName     = "wrappers"
	harnessCmdDir       = "cmd/scp-harness"
)

var (
	errEmptyLock             = errors.New("generate: lock file is empty")
	errNoSelectableEntries   = errors.New("generate: no entries selected")
	errRequestedEntryMissing = errors.New("generate: requested entry missing")
	errLocalPathMissingLabel = errors.New("generate: local path entry missing path label")
	errInvalidInputPath      = errors.New("generate: invalid input path")
	errUnsupportedModuleMode = errors.New("generate: unsupported module mode")
)

type generationConfig struct {
	Header      string
	APIName     string
	OutDir      string
	Entries     []scp.LockEntry
	FeatureSpec featureSpec
	Repository  string
}

func Run(ctx context.Context, opts Options) error {
	cfg, err := prepareConfig(opts)
	if err != nil {
		return err
	}

	return executeGeneration(cfg)
}

func validateOptions(opts Options) error {
	if opts.LockPath == "" {
		return errMissingLockPath
	}
	if opts.OutputDir == "" {
		return errMissingOutputDir
	}
	if opts.APIName == "" {
		return errMissingAPIName
	}
	if opts.ModuleMode != "" && opts.ModuleMode != DefaultModuleMode && opts.ModuleMode != ModuleModeRemote {
		return fmt.Errorf("%w: %s", errUnsupportedModuleMode, opts.ModuleMode)
	}

	return nil
}

func prepareConfig(opts Options) (generationConfig, error) {
	opts = opts.WithDefaults()

	if err := validateOptions(opts); err != nil {
		return generationConfig{}, err
	}

	lock, err := scp.ReadLock(opts.LockPath)
	if err != nil {
		return generationConfig{}, fmt.Errorf("generate: read lock: %w", err)
	}
	features, err := loadFeatureSpec(opts.FeaturesPath)
	if err != nil {
		return generationConfig{}, fmt.Errorf("generate: read features: %w", err)
	}
	header, err := buildHeader(opts.LicensePath)
	if err != nil {
		return generationConfig{}, fmt.Errorf("generate: build header: %w", err)
	}
	entries, err := selectEntries(lock, opts.OnlyNames)
	if err != nil {
		return generationConfig{}, err
	}

	outDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return generationConfig{}, fmt.Errorf("generate: resolve output dir: %w", err)
	}

	repo := "https://github.com/pion/sctp"
	if lock.Metadata.Repository != "" {
		repo = lock.Metadata.Repository
	}

	return generationConfig{
		Header:      header,
		APIName:     opts.APIName,
		OutDir:      outDir,
		Entries:     entries,
		FeatureSpec: features,
		Repository:  repo,
	}, nil
}

func executeGeneration(cfg generationConfig) error {
	if err := os.RemoveAll(cfg.OutDir); err != nil {
		return fmt.Errorf("generate: clear output dir: %w", err)
	}
	if err := os.MkdirAll(cfg.OutDir, 0o750); err != nil {
		return fmt.Errorf("generate: create output dir: %w", err)
	}

	if err := writeRootModule(cfg.OutDir); err != nil {
		return err
	}
	if err := writeAPIPackage(cfg.OutDir, cfg.Header, cfg.APIName); err != nil {
		return err
	}

	wrappers := make([]wrapperInfo, 0, len(cfg.Entries))
	for _, entry := range cfg.Entries {
		depInfo, err := stageInternalDependency(cfg.OutDir, cfg.Repository, entry)
		if err != nil {
			return err
		}

		wrapper, err := writeWrapper(cfg.OutDir, cfg.Header, entry, depInfo)
		if err != nil {
			return err
		}
		wrappers = append(wrappers, wrapper)
	}

	featureMatrix := computeEntryFeatures(wrappers, cfg.FeatureSpec)
	if err := writeHarness(cfg.OutDir, cfg.Header, wrappers, featureMatrix); err != nil {
		return err
	}

	return writeHarnessCommand(cfg.OutDir, cfg.Header)
}

type wrapperInfo struct {
	Entry        scp.LockEntry
	PackageName  string
	ImportPath   string
	FactoryAlias string
}

type dependencyInfo struct {
	ModulePath string
	ImportPath string
}

func selectEntries(lock *scp.Lockfile, only []string) ([]scp.LockEntry, error) {
	if lock == nil {
		return nil, errEmptyLock
	}

	allow := normalizeAllowList(only)
	var selected []scp.LockEntry
	for _, entry := range lock.Entries {
		if len(allow) > 0 {
			if _, ok := allow[entry.Name]; !ok {
				continue
			}
		}
		selected = append(selected, entry)
	}

	if err := ensureRequestedEntriesPresent(selected, allow); err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return nil, errNoSelectableEntries
	}

	sort.Slice(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })

	return selected, nil
}

func writeRootModule(outDir string) error {
	goModPath := filepath.Join(outDir, "go.mod")
	content := "module " + rootModulePath + "\n\ngo 1.21\n\nrequire github.com/pion/transport v0.15.2\n"
	data := []byte(content)

	return os.WriteFile(goModPath, data, 0o600)
}

func writeAPIPackage(outDir, header, apiName string) error {
	apiDir := filepath.Join(outDir, apiPackageName)
	if err := os.MkdirAll(apiDir, 0o750); err != nil {
		return fmt.Errorf("generate: create api dir: %w", err)
	}

	pkg := fmt.Sprintf(`%spackage %s

// Adapter represents a minimal SCTP adapter implementation.
type Adapter interface {
	// Name returns a human readable adapter name.
	Name() string
}

// DialRequest contains placeholder dial parameters.
type DialRequest struct {
	Remote string
}
`, header, apiName)

	return os.WriteFile(filepath.Join(apiDir, "sctp_api.go"), []byte(pkg), 0o600)
}

func stageInternalDependency(outDir string, repo string, entry scp.LockEntry) (dependencyInfo, error) {
	sourcePath, err := resolveSourcePath(repo, entry)
	if err != nil {
		return dependencyInfo{}, err
	}

	depDir := filepath.Join(outDir, internalDepsDirName, entry.Name)
	if err := copyTree(sourcePath, depDir); err != nil {
		return dependencyInfo{}, fmt.Errorf("generate: copy %s: %w", entry.Name, err)
	}

	modulePath := strings.Join([]string{rootModulePath, internalDepsDirName, entry.Name}, "/")
	if err := rewriteModule(depDir, modulePath); err != nil {
		return dependencyInfo{}, err
	}
	if err := rewriteImports(depDir, "github.com/pion/sctp", modulePath); err != nil {
		return dependencyInfo{}, err
	}

	return dependencyInfo{ModulePath: modulePath, ImportPath: modulePath}, nil
}

func writeWrapper(outDir, header string, entry scp.LockEntry, dep dependencyInfo) (wrapperInfo, error) {
	pkgName := sanitizePackage(entry.Name)
	wrapperDir := filepath.Join(outDir, wrappersDirName, entry.Name)
	if err := os.MkdirAll(wrapperDir, 0o750); err != nil {
		return wrapperInfo{}, fmt.Errorf("generate: create wrapper dir: %w", err)
	}

	content := fmt.Sprintf(`%spackage %s

import (
	adapter %q
	api %q
)

// Adapter is a placeholder implementation for %s.
type Adapter struct{}

// New returns a new Adapter instance.
func New() api.Adapter {
	return &Adapter{}
}

// Name returns the adapter identifier.
func (a *Adapter) Name() string {
	return %q
}
`, header, pkgName, dep.ImportPath, rootModulePath+"/"+apiPackageName, entry.Name, entry.Name)

	if err := os.WriteFile(filepath.Join(wrapperDir, "adapter.go"), []byte(content), 0o600); err != nil {
		return wrapperInfo{}, fmt.Errorf("generate: write wrapper for %s: %w", entry.Name, err)
	}

	return wrapperInfo{
		Entry:        entry,
		PackageName:  pkgName,
		ImportPath:   strings.Join([]string{rootModulePath, wrappersDirName, entry.Name}, "/"),
		FactoryAlias: "wrapper_" + pkgName,
	}, nil
}

func writeHarness(outDir, header string, wrappers []wrapperInfo, featureMatrix map[string][]string) error {
	harnessDir := filepath.Join(outDir, harnessPackageName)
	if err := os.MkdirAll(harnessDir, 0o750); err != nil {
		return fmt.Errorf("generate: create harness dir: %w", err)
	}

	imports := make([]string, 0, len(wrappers))
	for _, wrapper := range wrappers {
		imports = append(imports, fmt.Sprintf("    %s \"%s\"", wrapper.FactoryAlias, wrapper.ImportPath))
	}
	sort.Strings(imports)

	registryEntries := make([]string, 0, len(wrappers))
	for _, wrapper := range wrappers {
		registryEntries = append(registryEntries, fmt.Sprintf("    %q: %s.New,", wrapper.Entry.Name, wrapper.FactoryAlias))
	}
	sort.Strings(registryEntries)

	matrixEntries := make([]string, 0, len(featureMatrix))
	for name, features := range featureMatrix {
		matrixEntries = append(matrixEntries, fmt.Sprintf("    %q: %#v,", name, features))
	}
	sort.Strings(matrixEntries)

	var builder strings.Builder
	builder.WriteString(header)
	builder.WriteString("package ")
	builder.WriteString(harnessPackageName)
	builder.WriteString("\n\nimport (\n")
	builder.WriteString(strings.Join(imports, "\n"))
	if len(imports) > 0 {
		builder.WriteByte('\n')
	}
	builder.WriteString("    api \"")
	builder.WriteString(rootModulePath + "/" + apiPackageName)
	builder.WriteString("\"\n)\n\n")
	builder.WriteString("type AdapterFactory func() api.Adapter\n\n")
	builder.WriteString("var Registry = map[string]AdapterFactory{\n")
	builder.WriteString(strings.Join(registryEntries, "\n"))
	if len(registryEntries) > 0 {
		builder.WriteByte('\n')
	}
	builder.WriteString("}\n\nvar EntryFeatures = map[string][]string{\n")
	builder.WriteString(strings.Join(matrixEntries, "\n"))
	if len(matrixEntries) > 0 {
		builder.WriteByte('\n')
	}
	builder.WriteString("}\n")

	return os.WriteFile(filepath.Join(harnessDir, "registry.go"), []byte(builder.String()), 0o600)
}

func writeHarnessCommand(outDir, header string) error {
	cmdDir := filepath.Join(outDir, harnessCmdDir)
	if err := os.MkdirAll(cmdDir, 0o750); err != nil {
		return fmt.Errorf("generate: create harness cmd dir: %w", err)
	}

	mainFile := fmt.Sprintf(`%spackage main

import (
	"fmt"

	"github.com/pion/transport/vnet"
	harness %q
)

func main() {
	router := vnet.NewRouter()
	defer func() {
		_ = router.Stop()
	}()

	fmt.Println("registered adapters:")
	for name := range harness.Registry {
		fmt.Printf(" - %%s\n", name)
	}
}
`, header, rootModulePath+"/"+harnessPackageName)

	return os.WriteFile(filepath.Join(cmdDir, "main.go"), []byte(mainFile), 0o600)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git/") {
			if dirEntry.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}
		target := filepath.Join(dst, rel)
		if dirEntry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if !dirEntry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return err
		}

		return os.WriteFile(target, data, 0o600)
	})
}

func rewriteModule(dir, modulePath string) error {
	goModPath := filepath.Join(dir, "go.mod")
	cleanPath := filepath.Clean(goModPath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return fmt.Errorf("generate: read go.mod: %w", err)
	}
	file, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return fmt.Errorf("generate: parse go.mod: %w", err)
	}

	if file.Module == nil {
		if addErr := file.AddModuleStmt(modulePath); addErr != nil {
			return fmt.Errorf("generate: set module path: %w", addErr)
		}
	} else {
		file.Module.Mod.Path = modulePath
	}
	if file.Go == nil {
		if addErr := file.AddGoStmt("1.21"); addErr != nil {
			return fmt.Errorf("generate: set go version: %w", addErr)
		}
	} else {
		file.Go.Version = "1.21"
	}

	newData, err := file.Format()
	if err != nil {
		return fmt.Errorf("generate: format go.mod: %w", err)
	}

	return os.WriteFile(cleanPath, newData, 0o600)
}

func rewriteImports(dir, oldPath, newPath string) error {
	return filepath.WalkDir(dir, func(path string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dirEntry.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}

		cleanPath := filepath.Clean(path)
		data, err := os.ReadFile(cleanPath)
		if err != nil {
			return err
		}
		updated := strings.ReplaceAll(string(data), oldPath, newPath)
		if updated == string(data) {
			return nil
		}

		return os.WriteFile(cleanPath, []byte(updated), 0o600)
	})
}

func sanitizePackage(name string) string {
	mapped := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r - 'A' + 'a'
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}

		return '_'
	}, name)

	mapped = strings.Trim(mapped, "_")
	if mapped == "" {
		return "entry"
	}
	if mapped[0] >= '0' && mapped[0] <= '9' {
		mapped = "x" + mapped
	}

	return mapped
}

func normalizeAllowList(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}

	return set
}

func ensureRequestedEntriesPresent(entries []scp.LockEntry, required map[string]struct{}) error {
	if len(required) == 0 {
		return nil
	}
	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		present[entry.Name] = struct{}{}
	}
	for name := range required {
		if _, ok := present[name]; !ok {
			return fmt.Errorf("%w: %s", errRequestedEntryMissing, name)
		}
	}

	return nil
}

func resolveSourcePath(repo string, entry scp.LockEntry) (string, error) {
	if entry.Provenance == "local-path" {
		if path, ok := entry.Labels["path"]; ok && path != "" {
			return path, nil
		}

		return "", fmt.Errorf("%w: %s", errLocalPathMissingLabel, entry.Name)
	}

	cacheRoot, err := filepath.Abs(scp.DefaultCacheDir())
	if err != nil {
		return "", fmt.Errorf("generate: resolve cache root: %w", err)
	}
	checkoutDir := filepath.Join(
		cacheRoot,
		"checkouts",
		fmt.Sprintf("%s@%s", entry.Name, sanitizePathFragment(entry.Commit)),
	)
	if _, statErr := os.Stat(checkoutDir); statErr != nil {
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("generate: stat checkout %s: %w", checkoutDir, statErr)
		}
		if err := cloneRevision(repo, entry.Commit, checkoutDir); err != nil {
			return "", err
		}
	}

	return checkoutDir, nil
}

func cloneRevision(repo, commit, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return fmt.Errorf("generate: prepare checkout: %w", err)
	}
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	clone := exec.Command("git", "clone", "--no-checkout", repo, dest)
	clone.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := clone.CombinedOutput(); err != nil {
		return fmt.Errorf("generate: git clone %s: %w (output: %s)", repo, err, output)
	}

	checkout := exec.Command("git", "-C", dest, "checkout", commit)
	checkout.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := checkout.CombinedOutput(); err != nil {
		return fmt.Errorf("generate: git checkout %s: %w (output: %s)", commit, err, output)
	}

	return nil
}

func computeEntryFeatures(wrappers []wrapperInfo, spec featureSpec) map[string][]string {
	since := parseFeatureVersions(spec.Features)
	overrides := spec.Overrides
	result := make(map[string][]string, len(wrappers))
	for _, wrapper := range wrappers {
		result[wrapper.Entry.Name] = featuresForEntry(wrapper.Entry, since, overrides)
	}

	return result
}

func parseFeatureVersions(definitions []featureDefinition) map[string]*semver.Version {
	result := make(map[string]*semver.Version, len(definitions))
	for _, definition := range definitions {
		if definition.Since == "" {
			continue
		}
		version, err := semver.NewVersion(normalizeSemver(definition.Since))
		if err != nil {
			continue
		}
		result[definition.Name] = version
	}

	return result
}

func loadFeatureSpec(path string) (featureSpec, error) {
	if path == "" {
		return featureSpec{}, nil
	}
	data, err := readFileSafe(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return featureSpec{}, nil
		}

		return featureSpec{}, err
	}

	var spec featureSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return featureSpec{}, err
	}

	return spec, nil
}

func normalizeSemver(input string) string {
	if strings.HasPrefix(input, "v") {
		return input
	}

	return "v" + input
}

func featuresForEntry(
	entry scp.LockEntry,
	featureSince map[string]*semver.Version,
	overrides map[string]featureOverride,
) []string {
	enabled := map[string]struct{}{}

	if after, ok := strings.CutPrefix(entry.Selector, "tag:"); ok {
		tag := after
		version, err := semver.NewVersion(normalizeSemver(tag))
		if err == nil {
			for name, since := range featureSince {
				if !version.LessThan(since) {
					enabled[name] = struct{}{}
				}
			}
		}
	}

	if override, ok := overrides[entry.Name]; ok {
		for _, feat := range override.Enable {
			enabled[feat] = struct{}{}
		}
		for _, feat := range override.Disable {
			delete(enabled, feat)
		}
	}

	return setToSortedSlice(enabled)
}

func setToSortedSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)

	return items
}

func readFileSafe(path string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	if cleaned == "" || cleaned == "." {
		return nil, fmt.Errorf("%w: %s", errInvalidInputPath, path)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w: %s", errInvalidInputPath, path)
	}

	return os.ReadFile(cleaned)
}

func buildHeader(licensePath string) (string, error) {
	var buf strings.Builder
	if licensePath != "" {
		content, err := readFileSafe(licensePath)
		if err != nil {
			return "", err
		}
		lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
		for _, line := range lines {
			buf.WriteString("// ")
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
		if len(lines) > 0 {
			buf.WriteByte('\n')
		}
	}
	buf.WriteString("// Code generated by scp generate; DO NOT EDIT.\n\n")

	return buf.String(), nil
}

func sanitizePathFragment(value string) string {
	value = strings.ReplaceAll(value, string(filepath.Separator), "_")
	value = strings.ReplaceAll(value, ":", "_")
	if value == "" {
		return "unknown"
	}

	return value
}

type featureSpec struct {
	Schema    int                        `yaml:"schema"`
	Features  []featureDefinition        `yaml:"features"`
	Overrides map[string]featureOverride `yaml:"overrides"`
	Scenarios []scenarioDefinition       `yaml:"scenarios"`
}

type featureDefinition struct {
	Name  string `yaml:"name"`
	Since string `yaml:"since"`
}

type featureOverride struct {
	Enable  []string `yaml:"enable"`
	Disable []string `yaml:"disable"`
}

type scenarioDefinition struct {
	ID       string   `yaml:"id"`
	Requires []string `yaml:"requires"`
}
