use std::{
    fs,
    path::{Path, PathBuf},
};

const NOT_ALLOWED: [&str; 2] = [concat!("to", "do!"), concat!("TO", "DO:")];

#[test]
fn all_todo_done() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let errors: Vec<_> = dir
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|dir_entry| dir_entry.path())
        .filter(|path| {
            !matches!(
                path.file_name().unwrap().to_string_lossy().as_ref(),
                "target"
            )
        })
        .flat_map(test_dir)
        .collect();
    for (file, line) in &errors {
        let file = file.strip_prefix(dir).unwrap_or(file);
        eprintln!("{file:?}:{line}: Contains a some todo");
    }
    assert!(errors.is_empty(), "Some files contains a todo");
}

fn test_dir<P: AsRef<Path>>(path: P) -> Vec<(PathBuf, usize)> {
    let path = path.as_ref();
    if path.is_file() {
        if path.extension() == Some("png".as_ref()) {
            return vec![];
        }
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                eprintln!("fails to read {path:?}: {err}");
                return vec![];
            }
        };
        content
            .lines()
            .enumerate()
            .filter(|(_, line)| NOT_ALLOWED.iter().any(|s| line.contains(s)))
            .map(|(line, _)| (path.to_path_buf(), line + 1))
            .collect()
    } else {
        path.read_dir()
            .unwrap()
            .map(Result::unwrap)
            .map(|dir_entry| dir_entry.path())
            .flat_map(test_dir)
            .collect()
    }
}
