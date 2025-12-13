//! Gestion des bases de données pour les utilisateurs, tokens, et emails.

use std::{
    any::type_name,
    borrow::Borrow,
    collections::HashMap,
    fs::{File, create_dir_all},
    hash::Hash,
    path::{Path, PathBuf},
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use eyre::eyre;
use eyre::{Context, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::auth::ConnectedAdministrator;

pub struct DbTable<T> {
    path: PathBuf,
    datas: RwLock<T>,
}
impl<T: Serialize> DbTable<T> {
    /// Fonctions de sauvegarde et chargement YAML
    pub fn save(&self) -> Result<()> {
        // Crée le dossier parent s'il n'existe pas
        if let Some(parent_dir) = self.path.parent() {
            // had to change this, had this error:
            // error[E0658]: let expressions in this position are unstable
            if !parent_dir.exists() {
                create_dir_all(parent_dir).wrap_err("Failed to create directory")?;
            }
        }

        let file = File::create(&self.path)?;
        let data = self.read().map_err(|_| eyre!("DB poisoned"))?;
        serde_json::to_writer_pretty(file, &*data).wrap_err("Failed to serialize DB")?;
        Ok(())
    }
}
impl<K: Serialize, V: Serialize> DbTable<HashMap<K, V>> {
    pub fn clear(&self, _admin: &ConnectedAdministrator) -> Result<()> {
        self.write()?.clear();
        self.save()
    }
}

impl<T: Default + DeserializeOwned> DbTable<T> {
    pub fn load(path: &Path) -> Result<DbTable<T>> {
        // Chargement de la base de données depuis le fichier JSON
        if let Ok(file) = File::open(path) {
            let db_content: T = serde_json::from_reader(file).unwrap_or_default();
            Ok(DbTable {
                path: path.to_path_buf(),
                datas: RwLock::new(db_content),
            })
        } else {
            Ok(DbTable {
                path: path.to_path_buf(),
                datas: Default::default(),
            })
        }
    }
}
impl<T> DbTable<T> {
    fn write(&self) -> Result<RwLockWriteGuard<'_, T>> {
        self.datas
            .write()
            .map_err(|_| eyre!("DB poisoned ({})", type_name::<T>()))
    }
    pub fn read(&self) -> Result<RwLockReadGuard<'_, T>> {
        self.datas
            .read()
            .map_err(|_| eyre!("DB poisoned ({})", type_name::<T>()))
    }
}
impl<K: Eq + Hash, V> DbTable<HashMap<K, V>> {
    pub fn create(&self, key: K, value: V) -> Result<bool>
    where
        K: Serialize,
        V: Serialize,
    {
        {
            let mut db = self.write()?;

            if db.contains_key(&key) {
                return Ok(false);
            }
            db.insert(key, value);
        }
        self.save()?;
        Ok(true)
    }
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
        V: Clone,
    {
        self.read().ok()?.get(key).cloned()
    }
    pub fn exists<Q>(&self, key: &Q) -> Result<bool>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
        V: Clone,
    {
        Ok(self.read()?.contains_key(key))
    }
}

// Gestion des utilisateurs
pub mod user {

    use reqwest::Url;

    use super::*;

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct UserDb {
        pub id: u64,
        pub login: String,
        pub avatar: Option<Url>,
        pub name: Option<String>,
        pub liked_posts: Vec<u64>,
    }

    pub type Db = DbTable<HashMap<u64, UserDb>>;

    impl Db {
        pub fn insert_user(&self, user: UserDb) -> Result<()> {
            self.write()?.insert(user.id, user);
            self.save()?;
            Ok(())
        }
    }
}

pub mod post {
    use crate::auth::ConnectedUser;

    use super::*;

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct Post {
        pub id: u64,
        pub author: u64,
        pub text: String,
        pub image_path: Option<PathBuf>,
        pub likes: i32,
    }

    pub type Db = DbTable<HashMap<u64, Post>>;

    impl Db {
        pub async fn add_like(&self, _user: &ConnectedUser, post_id: u64) -> Result<()> {
            {
                let mut db = self.write()?;
                if let Some(a) = db.get_mut(&post_id) {
                    a.likes += 1;
                }
            }
            self.save()?;
            Ok(())
        }
        pub async fn del_like(&self, _user: &ConnectedUser, post_id: u64) -> Result<()> {
            {
                let mut db = self.write()?;
                if let Some(a) = db.get_mut(&post_id) {
                    a.likes -= 1;
                }
            }
            self.save()?;
            Ok(())
        }
        pub async fn create_post(
            &self,
            user: &ConnectedUser,
            text: String,
            image: Option<&Path>,
        ) -> Result<()> {
            {
                let mut db = self.write()?;
                let id = db.keys().max().copied().unwrap_or_default() + 1;
                let image_path = if let Some(image) = image {
                    let image_path = Path::new("image").join(id.to_string());
                    std::fs::create_dir_all(Path::new("image"))?;
                    std::fs::copy(image, &image_path)?;
                    Some(image_path)
                } else {
                    None
                };

                db.insert(
                    id,
                    Post {
                        id,
                        author: user.id(),
                        text,
                        image_path,
                        likes: 0,
                    },
                );
            }
            self.save()?;
            Ok(())
        }
    }
}
