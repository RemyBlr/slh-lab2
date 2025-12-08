use eyre::eyre;
use reqwest::Url;
use rocket::{
    http::Status,
    outcome::{IntoOutcome, try_outcome},
    request::{FromRequest, Outcome},
};
use serde::Serialize;

use crate::database::user;

#[derive(Serialize)]
pub struct ConnectedUser {
    id: u64,
    name: String,
    avatar: Option<Url>,
}
impl ConnectedUser {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn avatar(&self) -> Option<&Url> {
        self.avatar.as_ref()
    }
}

#[derive(Serialize)]
pub struct ConnectedAdministrator {
    user: ConnectedUser,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ConnectedUser {
    type Error = eyre::Report;

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        let Some(users) = request.rocket().state::<user::Db>() else {
            return Outcome::Error((Status::InternalServerError, eyre!("users DB not loaded")));
        };

        cookies
            .get_private(todo!())
            .and_then(|cookie| cookie.value().parse().ok())
            .and_then(|id| users.get(&id))
            .map(|user_db| ConnectedUser {
                id: user_db.id,
                name: user_db.name.unwrap_or(user_db.login),
                avatar: user_db.avatar,
            })
            .or_forward(Status::Unauthorized)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ConnectedAdministrator {
    type Error = eyre::Report;

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let user = try_outcome!(request.guard::<ConnectedUser>().await);

        if user.id == 44269255 {
            Outcome::Success(ConnectedAdministrator { user })
        } else {
            Outcome::Forward(Status::Unauthorized)
        }
    }
}
