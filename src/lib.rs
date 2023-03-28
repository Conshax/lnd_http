use std::collections::HashMap;

use base64::Engine;

use reqwest::{
    self,
    header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderValue},
};
use serde::{Deserialize, Serialize};
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

    #[error("Hex Error: {0}")]
    HexError(#[from] hex::FromHexError),
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

    pub async fn send_keysend(
        &self,
        dest_hex: &str,
        amt_msat: u64,
        mut dest_custom_records_slice: HashMap<u64, &[u8]>,
        outgoing_chan_id: Option<u64>,
    ) -> Result<[u8; 32]> {
        let mut pre_image = [0u8; 32];
        getrandom::getrandom(&mut pre_image)?;
        dest_custom_records_slice.insert(5482373484, &pre_image);

        let mut hasher = Sha256::new();
        hasher.update(pre_image);
        let payment_hash = slice_to_b64(hasher.finalize().as_slice());

        let dest_b64 = hex_to_base64(dest_hex)?;
        let dest_custom_records_b64 = dest_custom_records_slice
            .into_iter()
            .map(|(k, v)| (k, slice_to_b64(v)))
            .collect();

        let request_body = SendRequestBody {
            dest: dest_b64,
            amt_msat,
            payment_hash,
            dest_custom_records: dest_custom_records_b64,
            outgoing_chan_id,
        };

        let resp = self
            .reqwest_client
            .post(self.node_url.to_owned() + "/v1/channels/transactions")
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

    pub async fn add_invoice(
        &self,
        invoice: AddInvoiceRequestBody,
    ) -> Result<AddInvoiceResponseBody> {
        let resp = self
            .reqwest_client
            .post(self.node_url.to_owned() + "/v1/invoices")
            .json(&invoice)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            Err(Error::HttpResponseError(resp))
        }
    }
}

fn hex_to_base64(hex_str: &str) -> Result<String> {
    let bytes = hex::decode(hex_str)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()))
}

fn slice_to_b64(slice: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(slice)
}

#[derive(Serialize, Deserialize)]
pub struct AddInvoiceRequestBody {
    pub memo: Option<String>,

    pub value_msat: u64,

    pub expiry: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddInvoiceResponseBody {
    r_hash: String,

    payment_request: String,
}

//TODO implement missing https://github.com/lightningnetwork/lnd/blob/d44823f6e8580d2fa5f193a5382be351610f7c2b/lnrpc/lightning.proto#L769
#[derive(Serialize)]
struct SendRequestBody {
    pub dest: String, //base 64 encoded bytes
    pub amt_msat: u64,
    pub payment_hash: String,                      //base 64 encoded bytes
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

    #[tokio::test]
    async fn test_add_invoice() {
        let node_url = std::env::var("LND_NODE_URL").expect("Missing LND_NODE_URL env");
        let macaroon =
            std::env::var("CONSHAX_NODE_MACAROON").expect("Missing CONSHAX_NODE_MACAROON env");

        let client = Client::new(node_url, &macaroon);
        assert!(client.is_ok());
        let client = client.unwrap();

        let invoice = AddInvoiceRequestBody {
            memo: Some("test".to_string()),
            value_msat: 1000,
            expiry: None,
        };

        let res = client.add_invoice(invoice).await;
        dbg!(&res);

        assert!(res.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_send_keysend() {
        let node_url = std::env::var("LND_NODE_URL").expect("Missing LND_NODE_URL env");
        let macaroon =
            std::env::var("CONSHAX_NODE_MACAROON").expect("Missing CONSHAX_NODE_MACAROON env");
        let destination =
            std::env::var("ALBY_NODE_ADDRESS").expect("Missing ALBY_NODE_ADDRESS env");
        let custom_value = std::env::var("ALBY_TEST_USER_CUSTOM_VALUE")
            .expect("Missing ALBY_TEST_USER_CUSTOM_VALUE env");

        let client = Client::new(node_url, &macaroon);
        assert!(client.is_ok());
        let client = client.unwrap();

        let custom_records = HashMap::from_iter([(696969, custom_value.as_bytes())]);

        let res = client
            .send_keysend(&destination, 1000, custom_records, None)
            .await;

        if matches!(res, Ok(_)) {
        } else {
            dbg!(&res);
            panic!();
        }
    }
}
