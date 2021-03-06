use crate::permissions::Claim;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum IAMRequest {
    UsersList,
    UsersGetProfile(i64),
    RolesList,
    RoleGet(i64),
    RoleSave(RoleSummary),
    RoleDelete(i64),
    PermissionStatementGet(i64),
    PermissionStatementSave(PermissionStatement),
    PermissionStatemenetDelete(i64),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum IAMResponse {
    UsersList(Vec<User>),
    RolesList(Vec<RoleSummary>),
    UserProfile(User),
    Role(Role),
    RoleSaved(i64),
    RoleDeleted(i64),
    PermissionStatement(PermissionStatement),
    PermissionStatementSaved(i64),
    PermissionStatementDeleted(i64),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub id: Option<i64>,
    pub screenname: Option<String>,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<RoleSummary>,
}

pub fn users_list_claim() -> Claim {
    Claim::new("iam", Some("users"), None, "list")
}

pub fn users_read_claim(id: Option<i64>) -> Claim {
    Claim::new("iam", Some("users"), id, "read")
}

pub fn users_update_claim(id: Option<i64>) -> Claim {
    Claim::new("iam", Some("users"), id, "update")
}

pub fn users_create_claim() -> Claim {
    Claim::new("iam", Some("users"), None, "create")
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RoleSummary {
    pub id: Option<i64>,
    pub name: String,
}

pub fn roles_list_claim() -> Claim {
    Claim::new("iam", Some("roles"), None, "list")
}

pub fn roles_read_claim(id: Option<i64>) -> Claim {
    Claim::new("iam", Some("roles"), id, "read")
}

pub fn roles_update_claim(id: Option<i64>) -> Claim {
    Claim::new("iam", Some("roles"), id, "update")
}

pub fn roles_create_claim() -> Claim {
    Claim::new("iam", Some("roles"), None, "create")
}

pub fn roles_delete_claim(id: Option<i64>) -> Claim {
    Claim::new("iam", Some("roles"), id, "delete")
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub id: Option<i64>,
    pub name: String,
    pub permission_statements: Vec<PermissionStatement>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PermissionStatement {
    pub id: Option<i64>,
    pub role_id: Option<i64>,

    pub service: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,

    pub action: Option<String>,

    pub allow: bool,

    pub comment: Option<String>,
}
