use bytes::Bytes;
use rusoto_core::{credential::ProfileProvider, HttpClient, Region};
use rusoto_kms::{DecryptRequest, Kms, KmsClient};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use std::{env, fs::File, io::Read, process};

fn create_kms_client(region: &Region) -> KmsClient {
    let provider = ProfileProvider::new().unwrap();
    let dispatcher = HttpClient::new().unwrap();

    match env::var("RUST_ENV").unwrap_or_default().as_str() {
        "development" => match env::var("STS_ASSUME_ROLE_ARN") {
            Ok(val) => {
                let sts = StsClient::new(region.to_owned());
                let provider = StsAssumeRoleSessionCredentialsProvider::new(
                    sts,
                    val.to_owned(),
                    "default".to_owned(),
                    None,
                    None,
                    None,
                    None,
                );
                KmsClient::new_with(dispatcher, provider, region.to_owned())
            }
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(1);
            }
        },
        _ => KmsClient::new_with(dispatcher, provider, region.to_owned()),
    }
}

#[tokio::main]
async fn main() {
    let region = Region::ApNortheast1;
    let kms = create_kms_client(&region);

    let mut input = DecryptRequest::default();
    input.key_id = env::var("KMS_KEY_ID").ok();

    let mut file = File::open("static/twitter_consumer_key").unwrap();
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf).unwrap();
    input.ciphertext_blob = Bytes::from(buf);
    let plaintext = kms
        .decrypt(input.to_owned())
        .await
        .unwrap()
        .plaintext
        .unwrap();
    let consumer_key = String::from_utf8(plaintext.to_vec()).unwrap();

    let mut file = File::open("static/twitter_consumer_secret").unwrap();
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf).unwrap();
    input.ciphertext_blob = Bytes::from(buf);
    let plaintext = kms
        .decrypt(input.to_owned())
        .await
        .unwrap()
        .plaintext
        .unwrap();
    let consumer_secret = String::from_utf8(plaintext.to_vec()).unwrap();

    let mut file = File::open("static/twitter_access_key").unwrap();
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf).unwrap();
    input.ciphertext_blob = Bytes::from(buf);
    let plaintext = kms
        .decrypt(input.to_owned())
        .await
        .unwrap()
        .plaintext
        .unwrap();
    let access_key = String::from_utf8(plaintext.to_vec()).unwrap();

    let mut file = File::open("static/twitter_access_secret").unwrap();
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf).unwrap();
    input.ciphertext_blob = Bytes::from(buf);
    let plaintext = kms.decrypt(input).await.unwrap().plaintext.unwrap();
    let access_secret = String::from_utf8(plaintext.to_vec()).unwrap();

    let consumer_token = egg_mode::KeyPair::new(consumer_key, consumer_secret);
    let access_token = egg_mode::KeyPair::new(access_key, access_secret);
    let token = egg_mode::Token::Access {
        consumer: consumer_token,
        access: access_token,
    };

    let result = egg_mode::user::show("nijisanji_app", &token).await;

    match result {
        Ok(user) => println!("success.\nid: {}", user.response.id),
        Err(e) => println!("{}", e),
    }
}
