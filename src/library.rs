//! The library: versioned task and package definitions on disk.
//!
//! Layout, matching LibraryManager: `libraryRoot/group/name/version/<type>.json`, where `<type>`
//! is one of task, package, recipe or pipeline. The coordinate a recipe item names —
//! `com.colistor.app/create-app-database-pg/1.0` — is exactly the first three path segments.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    Task,
    Package,
    Recipe,
    Pipeline,
}

impl ItemType {
    pub fn folder_name(self) -> &'static str {
        match self {
            ItemType::Task => "task",
            ItemType::Package => "package",
            ItemType::Recipe => "recipe",
            ItemType::Pipeline => "pipeline",
        }
    }

    pub fn from_folder_name(name: &str) -> Option<Self> {
        match name {
            "task" => Some(ItemType::Task),
            "package" => Some(ItemType::Package),
            "recipe" => Some(ItemType::Recipe),
            "pipeline" => Some(ItemType::Pipeline),
            _ => None,
        }
    }

    /// From `"type": "blaster:task"`, or from a file literally named `task.json`.
    ///
    /// Deliberately NOT inferred from content. An earlier version guessed from the presence of a
    /// `tasks` key and installed 13 of this repository's 35 task files where the Kotlin CLI
    /// installs 2 — and the library is what execution reads, so a tool that installs more than the
    /// other is a tool that runs different code. Matching the stricter behaviour keeps one answer
    /// to "what is in the library"; the 33 files without a `type` are a data problem to fix in the
    /// files, not in the installer.
    pub fn from_declared(value: &Value, file_stem: &str) -> Option<Self> {
        if let Some(declared) = value.get("type").and_then(Value::as_str) {
            return match declared {
                "blaster:task" => Some(ItemType::Task),
                "blaster:package" => Some(ItemType::Package),
                "blaster:recipe" => Some(ItemType::Recipe),
                "blaster:pipeline" => Some(ItemType::Pipeline),
                _ => None,
            };
        }
        Self::from_folder_name(file_stem)
    }
}

#[derive(Debug, Clone)]
pub struct LibraryItem {
    pub group: String,
    pub name: String,
    pub version: String,
    pub item_type: ItemType,
}

impl LibraryItem {
    pub fn coordinate(&self) -> String {
        format!("{}/{}/{}", self.group, self.name, self.version)
    }
}

pub struct Library {
    pub root: PathBuf,
}

impl Library {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn item_file(&self, group: &str, name: &str, version: &str, item_type: ItemType) -> PathBuf {
        self.root
            .join(group)
            .join(name)
            .join(version)
            .join(format!("{}.json", item_type.folder_name()))
    }

    /// Install one JSON definition, keyed by the group/name/version it declares.
    pub fn install_file(&self, path: &Path, force: bool) -> Result<LibraryItem> {
        let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let value: Value = serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

        // The coordinate comes from the file's own fields, never from where it happens to sit.
        let group = value.get("group").and_then(Value::as_str)
            .with_context(|| format!("{} has no 'group' field", path.display()))?;
        let name = value.get("name").and_then(Value::as_str)
            .with_context(|| format!("{} has no 'name' field", path.display()))?;
        let version = value.get("version").and_then(Value::as_str)
            .with_context(|| format!("{} has no 'version' field", path.display()))?;

        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let item_type = ItemType::from_declared(&value, stem).with_context(|| {
            format!(
                "{} declares no library type — expected \"type\": \"blaster:task\" (or package/recipe/pipeline)",
                path.display()
            )
        })?;
        let target = self.item_file(group, name, version, item_type);

        if target.exists() && !force {
            anyhow::bail!(
                "{} already exists — pass --force to overwrite",
                target.display()
            );
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&target, raw.as_bytes()).with_context(|| format!("writing {}", target.display()))?;

        Ok(LibraryItem {
            group: group.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            item_type,
        })
    }

    /// Every item, walked as group/name/version/type.json.
    pub fn list(&self) -> Result<Vec<LibraryItem>> {
        let mut items = Vec::new();
        if !self.root.exists() {
            return Ok(items);
        }
        for group in read_dirs(&self.root)? {
            let group_name = file_name_of(&group);
            for name_dir in read_dirs(&group)? {
                let name = file_name_of(&name_dir);
                for version_dir in read_dirs(&name_dir)? {
                    let version = file_name_of(&version_dir);
                    for entry in fs::read_dir(&version_dir)?.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) != Some("json") {
                            continue;
                        }
                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                        if let Some(item_type) = ItemType::from_folder_name(stem) {
                            items.push(LibraryItem {
                                group: group_name.clone(),
                                name: name.clone(),
                                version: version.clone(),
                                item_type,
                            });
                        }
                    }
                }
            }
        }
        items.sort_by_key(|i| (i.group.clone(), i.name.clone(), i.version.clone()));
        Ok(items)
    }
}

fn read_dirs(path: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = fs::read_dir(path)
        .with_context(|| format!("reading {}", path.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    Ok(out)
}

fn file_name_of(path: &Path) -> String {
    path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_type_decides() {
        let task = serde_json::json!({"type": "blaster:task", "tasks": []});
        assert_eq!(ItemType::from_declared(&task, "anything"), Some(ItemType::Task));
    }

    #[test]
    fn a_type_named_file_is_accepted_when_nothing_is_declared() {
        let bare = serde_json::json!({"tasks": []});
        assert_eq!(ItemType::from_declared(&bare, "task"), Some(ItemType::Task));
    }

    #[test]
    fn content_alone_is_not_enough() {
        // Guessing from a `tasks` key installed 13 files where the Kotlin CLI installs 2.
        let bare = serde_json::json!({"tasks": []});
        assert_eq!(ItemType::from_declared(&bare, "create-postgresql-schema"), None);
    }

    #[test]
    fn install_then_list_round_trips_on_the_declared_coordinate() {
        let dir = std::env::temp_dir().join(format!("bigbang-lib-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.json");
        fs::write(&src, br#"{"type":"blaster:task","group":"com.x","name":"y","version":"1.0","tasks":[]}"#).unwrap();

        let library = Library::new(dir.join("lib"));
        let item = library.install_file(&src, false).unwrap();
        assert_eq!(item.coordinate(), "com.x/y/1.0");

        let listed = library.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].coordinate(), "com.x/y/1.0");
        assert_eq!(listed[0].item_type, ItemType::Task);

        // A second install without --force must refuse rather than silently replacing.
        assert!(library.install_file(&src, false).is_err());
        assert!(library.install_file(&src, true).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
