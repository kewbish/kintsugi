use crate::kintsugi_lib::keypair::PublicKey;
use crate::kintsugi_lib::{
    acss::ACSSDealerShare,
    opaque::{
        LoginStartRequest, LoginStartResponse, RegFinishRequest, RegStartRequest, RegStartResponse,
    },
};
use curve25519_dalek::RistrettoPoint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OPRFRegInitMessage {
    pub(crate) h_point: RistrettoPoint,
    pub(crate) reg_start_req: RegStartRequest,
    pub(crate) dealer_shares: HashMap<String, ACSSDealerShare>,
    pub(crate) dealer_key: PublicKey,
    pub(crate) user_username: String,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OPRFRegStartRespMessage {
    pub(crate) reg_start_resp: RegStartResponse,
    pub(crate) user_username: String,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OPRFRegFinishReqMessage {
    pub(crate) reg_finish_req: RegFinishRequest,
    pub(crate) user_username: String,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OPRFRecoveryStartReqMessage {
    pub(crate) recovery_start_req: LoginStartRequest,
    pub(crate) h_point: RistrettoPoint,
    pub(crate) user_username: String,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OPRFRecoveryStartRespMessage {
    pub(crate) recovery_start_resp: LoginStartResponse,
    pub(crate) h_point: RistrettoPoint,
    pub(crate) user_username: String,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DPSSRefreshInitMessage {
    pub(crate) new_recovery_addresses: HashMap<String, i32>,
    pub(crate) new_threshold: usize,
    pub(crate) old_committee_size: usize,
    pub(crate) user_username: String,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DPSSRefreshReshareMessage {
    pub(crate) h_point: RistrettoPoint,
    pub(crate) dealer_shares: HashMap<String, ACSSDealerShare>,
    pub(crate) dealer_shares_hat: HashMap<String, ACSSDealerShare>,
    pub(crate) old_commitment: RistrettoPoint,
    pub(crate) new_recovery_addresses: HashMap<String, i32>,
    pub(crate) dealer_key: PublicKey,
    pub(crate) new_threshold: usize,
    pub(crate) old_committee_size: usize,
    pub(crate) user_username: String,
    pub(crate) from_index: i32,
    pub(crate) node_index: i32,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DPSSRefreshCompleteMessage {
    pub(crate) new_threshold: usize,
    pub(crate) new_recovery_addresses: HashMap<String, i32>,
    pub(crate) user_username: String,
    pub(crate) node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum RequestMessage {
    OPRFRegInitMessage(OPRFRegInitMessage),
    OPRFRegFinishReqMessage(OPRFRegFinishReqMessage),
    OPRFRecoveryStartReqMessage(OPRFRecoveryStartReqMessage),
    DPSSRefreshInitMessage(DPSSRefreshInitMessage),
    DPSSRefreshReshareMessage(DPSSRefreshReshareMessage),
    DPSSRefreshCompleteMessage(DPSSRefreshCompleteMessage),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ResponseMessage {
    OPRFRegStartRespMessage(OPRFRegStartRespMessage),
    OPRFRecoveryStartRespMessage(OPRFRecoveryStartRespMessage),
}
