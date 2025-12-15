<!--
vim: spelllang=fr
-->
# SLH 2025 - Lab #2

- Laboratoire noté.
- Veuillez rendre **votre code** et le **README.md** répondant aux questions du
  chapitre `Question`.
- La qualité du code est notée.
- Le code doit obligatoirement être écrit en Rust.
- La **validation des entrées** est primordiale.
- Nous nous attendons à ce que vous testiez votre code.
- Vous trouverez dans le code fourni les fichiers à remplir. La partie frontend
  est déjà fournie dans son entièreté.
- La crate `openssl` nécessite d'avoir `openssl-dev` d'installé.
- **Ne pas modifier la version des dépendances de `cargo.toml`**. Vous pouvez
  cependant ajouter des crates si nécessaire.

## Description

Le but de ce laboratoire est de gérer l'authentification d'un site web.
L'authentification doit être gérée à travers le protocole OAuth2[^1] avec GitHub[^2]
et la crate `rocket_oauth2`[^3].
Les fonctionnalités du site sont les suivantes :

- Connexion avec un nouveau compte.
- Connexion à un compte existant.
- Publier une image et une courte description.

[^1]: <https://oauth.net/2/>
[^2]: <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app>
[^3]: <https://lib.rs/crates/rocket_oauth2>

## Rendu

Le `README.md` contenant les réponses aux questions et le code source dans une archive `.crate`.

Pour générer l'archive avec le code source, la commande :

```sh
cargo package
```

Génère l'archive dans le répertoire `target/package/`.

## Questions

> Répondez aux questions directement dans ce fichier là.

(Pour le bonus, j'ai mis des commentaires commencant par `// BONUS`  un peu partout dans `main.rs`).

1. Quel serait l'impact si on se fait voler notre secret client (et client id) ?

- Secret client : l'attaquant peut se faire passer pour notre app, il peut accéder aux
  ressources des utilisateurs qui ont autorisé notre app et il peut également échanger des codes d'authorization
  contre des tokens d'accès.
- Client ID : identifiant public, pas de risque si volé.

2. Comment peut-on protéger notre secret client, afin d'éviter qu'il soit publier ou voler ?

- Comme écrit dans le `Rocket.toml`, il ne faut pas commit le secret.
- Il ne faut pas non plus l'exposer dans le code source.
- Utiliser des variables d'environnement pour stocker le secret.
- Utiliser un fichier non versionné pour stocker le secret.

3. Quels est la différences entre OAuth2 et LDAP ?

- OAuth2 : C'est un protocole d'autorisation délégué  qui est basé sur des tokens d'accès (de cette façon, le mdp de l'user n'est pas partagé avec l'app).
- LDAP : C'est de l'authentification centralisée, qui elle est basée sur des identifiants (username/mdp). De ce fait, l'application doit gérer les mdp des utilisateurs.

4. Est-ce que le mot de passe transite par votre serveur ? Est-ce qu'on peut le voler ?

- D'après la réponse précédente, le mdp ne transite pas par le serveur. Il est géré par Github.
- Le serveur reçoit un `authorization code` suivi d'un `access token`.
- Il est donc impossible de voler le mdp.

5. Si vous êtes mal intentionné et que vous administrez un serveur utilisant l'OAuth2 Github. Comment ferriez-vous pour obtenir plus d'accès au nom de vos utilisateur ? Et donnez des exemples.

- En tant qu'admin, je peux modifier et mentir sur la portée demandée par l'app lors de la demande d'autorisation.
   - Par exemple, je pourrais demander l'accès en écriture aux repos Github des utilisateurs.
   - Je pourrais aussi supprimer des repos.
- Je pourrais stocker les `access tokens` des utilisateurs pour les réutiliser plus tard sans qu'il le sache.
   - Ça me permettrait de lire les emails des utilisateurs.

6. Pour les 2 captures d'écran d'écran de consentement de google, indiqué quels
   scopes on probablement été demander par le site web.

J'ai utilisé [ce lien (google dev)](https://developers.google.com/workspace/drive/api/guides/api-specific-auth?hl=fr) et
[ce lien (auth0)](https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes) pour comprendre chaque scope.

- Pour la première image :
   - On demande l'accès à Google Drive.
   - Accès aux fichiers Google Drive  qui ont été crées par l'app.
   - Le scope est donc : `https://www.googleapis.com/auth/drive.file`
   - [image 1](scope-01.png) ![](scope-01.png) ![](../../../scope-01.png)

- Pour la deuxième image :
   - On demande l'accès au nom et image de profile.
   - Le scope est donc : profile et openid (qui est apparemment obligatoire).
   - [image 2](scope-01.png) ![](../../../scope-02.png) ![](scope-02.png)

  Scopes possible (dans l'ordre alphabétique):
   - `email`
   - `https://example.com/all`
   - `https://www.googleapis.com/auth/documents`
   - `https://www.googleapis.com/auth/drive.file`
   - `https://www.googleapis.com/auth/drive.photos.readonly`
   - `https://www.googleapis.com/auth/drive.readonly`
   - `https://www.googleapis.com/auth/drive`
   - `https://www.googleapis.com/auth/gmail`
   - `openid`
   - `profile`

## Tâches principales

Pour lancer l'application vous devez être dans le même répertoire que `Cargo.toml` :

```sh
…$ ls -A
Cargo.lock  Cargo.toml  data  image  README.md  Rocket.toml  scope-01.png  scope-02.png  src  target  templates  tests
…$ cargo run
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running `target/debug/lab02-2025`
🔧 Configured for debug.
   >> address: 127.0.0.1
…
```

Compléter tout les `todo` du code, lors de `cargo test`, la liste des fichiers en contenant encore est affiché.

## Fournisseur OAuth2

Le fournisseur OAuth2 pour ce labo est Github; La création des token se passe sur la page : <https://github.com/settings/developers>.
