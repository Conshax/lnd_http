use std::collections::HashMap;

use base64::Engine;
use reqwest::{self, header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderValue}};
use getrandom;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {

    #[error("Invalid header value error: {0}")]
    InvalidHeaderError(#[from] InvalidHeaderValue),

    #[error("Reqwest Error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("getrandom Error: {0}")]
    GetRandomError(#[from] getrandom::Error),

    #[error("HttpResponse Error")]
    HttpResponseError(reqwest::Response),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Lnd Error: {0}")]
    LndError(String),
}

pub struct Client {
    reqwest_client: reqwest::Client,
    node_url: String,
}

impl Client {
    pub fn new(node_url: String, macaroon: &str) -> Result<Client> {

        let macaroon_header_name = HeaderName::from_static("grpc-metadata-macaroon");
        let mut macaroon_header_value = HeaderValue::from_str(macaroon)?;
        macaroon_header_value.set_sensitive(true);

        let headers = HeaderMap::from_iter([(macaroon_header_name, macaroon_header_value)]);

        let reqwest_client = reqwest::ClientBuilder::new()
            .default_headers(headers)
            .build()?;

        Ok(Client {
            reqwest_client,
            node_url,
        })
    }

    pub async fn send_keysend(&self, dest: String, amt_msat: u64, mut dest_custom_records: HashMap<u64, String>, outgoing_chan_id: Option<u64>) -> Result<[u8; 32]> {
        if dest.len() != 44 {
            return Err(Error::InvalidParameter(String::from("invalid dest length, needs to be 44")));
        }

        let mut pre_image = [0u8; 32];
        getrandom::getrandom(&mut pre_image)?;

        let pre_image_b64 = base64::engine::general_purpose::STANDARD.encode(&pre_image);
        dest_custom_records.insert(5482373484, pre_image_b64);

        let mut hasher = Sha256::new();
        hasher.update(pre_image);
        
        let payment_hash = hasher.finalize().to_vec();
        dbg!(hex::encode(&payment_hash));
        let payment_hash = base64::engine::general_purpose::STANDARD.encode(payment_hash);

        let request_body = SendRequestBody {
            dest,
            amt_msat,
            payment_hash,
            dest_custom_records,
            outgoing_chan_id,
        };

        let resp = self.reqwest_client.post(self.node_url.to_owned() + "/v1/channels/transactions")
        .json(&request_body)
        .send()
        .await?;

        if resp.status().is_success() {
            let response: SendResponseBody = resp.json().await?;

            if response.payment_error.trim().is_empty() {
                Ok(pre_image)
            } else {
                Err(Error::LndError(response.payment_error))
            }
        } else {
            Err(Error::HttpResponseError(resp))
        }
    }
}

//TODO implement missing https://github.com/lightningnetwork/lnd/blob/d44823f6e8580d2fa5f193a5382be351610f7c2b/lnrpc/lightning.proto#L769
#[derive(Serialize)]
struct SendRequestBody {
    pub dest: String, //base 64 encoded bytes
    pub amt_msat: u64,
    pub payment_hash: String, //base 64 encoded bytes
    pub dest_custom_records: HashMap<u64, String>, //base 64 encoded bytes
    pub outgoing_chan_id: Option<u64>,
}

#[derive(Deserialize)]
struct SendResponseBody {
    pub payment_error: String,
    //TODO other fields
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[tokio::test]
    async fn test_send_keysend() {
        let node_url = std::env::var("CONSHAX_NODE_URL").expect("Missing CONSHAX_NODE_URL env");
        let macaroon = std::env::var("CONSHAX_NODE_MACAROON").expect("Missing CONSHAX_NODE_MACAROON env");

        let client = Client::new(node_url, &macaroon);
        assert!(client.is_ok());
        let client = client.unwrap();

        let destination = std::env::var("ALBY_NODE_ADDRESS").expect("Missing ALBY_NODE_ADDRESS env");
        let dest_hex = hex::decode(destination).expect("Could not decode destination to hex");
        let dest_b64 = base64::engine::general_purpose::STANDARD.encode(dest_hex.as_slice());
    

        let custom_value = std::env::var("ALBY_TEST_USER_CUSTOM_VALUE"). expect("Missing ALBY_TEST_USER_CUSTOM_VALUE env");
        let custom_value_b64 = base64::engine::general_purpose::STANDARD.encode(custom_value);

        let custom_records = HashMap::from_iter([(696969, custom_value_b64)]);

        let res = client.send_keysend(dest_b64, 1000, custom_records, None).await;

        if matches!(res, Ok(_)) {
            assert!(true)            
        } else {
            dbg!(&res);
            assert!(false)
        }
    }
}
