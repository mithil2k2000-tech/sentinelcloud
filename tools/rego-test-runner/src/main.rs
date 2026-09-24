// A small, honest substitute for `opa test`.
//
// This project's build sandbox can't reach openpolicyagent.org to download
// the real `opa` binary (same class of network restriction that blocked
// `terraform` — see docs/phase1-*.md and docs/phase2-tests.md for the same
// pattern with python-hcl2 substituting for `terraform validate`). Rather
// than leave the OPA/Rego policy layer completely unverified, this tool
// uses `regorus` — Microsoft's real, independent Rego interpreter, not a
// mock — to actually load and evaluate every `.rego` file under a
// directory, discover OPA-convention `test_*` rules, and check that each
// one evaluates to `true`, the same pass/fail rule `opa test` itself uses.
//
// This is a genuine evaluation of real Rego semantics against the real
// policy files, not a syntax guess. What it does NOT claim to replicate:
// `opa test`'s exact CLI output format, coverage reporting, or the full
// conformance-test suite behind the reference implementation. Swap this
// tool for the real `opa test` the moment this project runs somewhere
// with normal network access (e.g. GitHub Actions, where the workflow
// already uses the real `open-policy-agent/setup-opa` action).

use anyhow::{bail, Context, Result};
use regex::Regex;
use regorus::{Engine, Value};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

struct DiscoveredTest {
    package: String,
    rule_name: String,
    source_file: PathBuf,
}

fn find_rego_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(ext) = entry.path().extension() {
                if ext == "rego" {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn package_of(source: &str) -> Option<String> {
    let re = Regex::new(r"(?m)^\s*package\s+([a-zA-Z0-9_.]+)").unwrap();
    re.captures(source).map(|c| c[1].to_string())
}

fn discover_tests(test_files: &[PathBuf]) -> Result<Vec<DiscoveredTest>> {
    let rule_re =
        Regex::new(r"(?m)^\s*(test_[a-zA-Z0-9_]+)\s*(\[.*?\])?\s*(if\s+)?(:?=|\{)").unwrap();
    let mut out = Vec::new();
    for f in test_files {
        let src = std::fs::read_to_string(f)
            .with_context(|| format!("reading {}", f.display()))?;
        let package = package_of(&src)
            .with_context(|| format!("{} has no `package` declaration", f.display()))?;
        for cap in rule_re.captures_iter(&src) {
            out.push(DiscoveredTest {
                package: package.clone(),
                rule_name: cap[1].to_string(),
                source_file: f.clone(),
            });
        }
    }
    Ok(out)
}

fn main() -> Result<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "policy/opa".to_string());
    let dir = Path::new(&dir);
    if !dir.is_dir() {
        bail!("policy directory not found: {}", dir.display());
    }

    let rego_files = find_rego_files(dir)?;
    if rego_files.is_empty() {
        bail!("no .rego files found under {}", dir.display());
    }

    let mut engine = Engine::new();
    for f in &rego_files {
        engine
            .add_policy_from_file(f)
            .with_context(|| format!("compiling {}", f.display()))?;
    }

    let test_files: Vec<PathBuf> = rego_files
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with("_test.rego"))
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    let tests = discover_tests(&test_files)?;
    if tests.is_empty() {
        // Fail closed rather than silently reporting a green gate for a
        // policy directory nobody actually wrote assertions for — same
        // principle as SR-11 in the v1 spec (§6): ambiguity blocks, it
        // never quietly passes.
        bail!(
            "no test_* rules discovered under {} — refusing to report success on zero tests",
            dir.display()
        );
    }

    println!("rego-test-runner: {} test(s) found\n", tests.len());

    let mut failures = Vec::new();
    for t in &tests {
        let path = format!("data.{}.{}", t.package, t.rule_name);
        let result = engine.eval_rule(path.clone());
        let (status, detail) = match result {
            Ok(Value::Bool(true)) => ("PASS", String::new()),
            Ok(Value::Bool(false)) => ("FAIL", "evaluated to false".to_string()),
            Ok(Value::Undefined) => ("FAIL", "evaluated to undefined".to_string()),
            Ok(other) => (
                "FAIL",
                format!("expected boolean true, got: {other:?}"),
            ),
            Err(e) => ("ERROR", format!("{e:#}")),
        };
        println!(
            "  [{status}] {}.{}  ({})",
            t.package,
            t.rule_name,
            t.source_file.display()
        );
        if status != "PASS" {
            failures.push((t, detail));
        }
    }

    println!();
    if failures.is_empty() {
        println!("{}/{} tests passed", tests.len(), tests.len());
        Ok(())
    } else {
        println!(
            "{}/{} tests passed — {} failed:",
            tests.len() - failures.len(),
            tests.len(),
            failures.len()
        );
        for (t, detail) in &failures {
            println!("  - {}.{}: {}", t.package, t.rule_name, detail);
        }
        bail!("{} rego test(s) failed", failures.len());
    }
}
