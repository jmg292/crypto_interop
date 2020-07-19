mod authentication;
mod messaging;
mod identity;

use crate::identity::authorized_hosts::AuthorizedHosts;
use crate::identity::objects::LocalIdentity;
use crate::messaging::wrapper::MessageWrapper;
use crate::authentication::Handshake;
use global::Global;


static AUTHORIZED_HOSTS: Global<AuthorizedHosts> = Global::new();
static MESSAGE_WRAPPER: Global<MessageWrapper> = Global::new();
static LOCAL_IDENTITY: Global<LocalIdentity> = Global::new();
static HANDSHAKE: Global<Handshake> = Global::new();


#[no_mangle] 
pub extern fn init(identity_file: &str, authorized_keys_folder: &str) {
    let mut local_identity = LOCAL_IDENTITY.lock_mut().unwrap();
    local_identity.load_from_file(&identity_file).expect("Unable to load identity key from file.");
    AUTHORIZED_HOSTS.lock_mut().unwrap().load_keys(authorized_keys_folder).expect("Unable to load Authorized Hosts directory.");
    HANDSHAKE.lock_mut().unwrap().load_local_identity(local_identity.clone());
}

#[no_mangle]
pub extern fn save_public_key(file_path: &str) -> bool {
    let mut return_value = false;
    if LOCAL_IDENTITY.lock().unwrap().to_remote_identity().save_to_file(file_path).is_ok() {
        return_value = true;
    }
    return return_value;
}

#[no_mangle]
pub extern fn get_challenge() -> [u8; 16] {
    HANDSHAKE.lock_mut().unwrap().challenge(true)
}

#[no_mangle] 
pub extern fn get_challenge_response(challenge: &[u8]) -> [u8; 193] {
    HANDSHAKE.lock_mut().unwrap().challenge_response(challenge)
}

#[no_mangle]
pub extern fn finalize_challenge(challenge_response: &[u8], output_buffer: &mut [u8]) -> bool {
    let mut return_value = false;
    let mut handshake = HANDSHAKE.lock_mut().unwrap();
    let challenge_finalization = handshake.finalize_challenge(challenge_response, &AUTHORIZED_HOSTS.lock().unwrap());
    if challenge_finalization.is_ok() {
        return_value = true;
        if MESSAGE_WRAPPER.lock_mut().unwrap().load_from_handshake(&handshake).is_ok() {
            let response_option = challenge_finalization.unwrap();
            if response_option.is_some() {
                let response = response_option.unwrap();
                for i in 0..response.len() {
                    output_buffer[i] = response[i];
                }
            }
        }
    }
    return return_value;
}

#[no_mangle]
pub extern fn encrypt(message: &[u8], output_buffer: &mut [u8]) -> bool {
    let mut return_value = false;
    let ciphertext_result = MESSAGE_WRAPPER.lock_mut().unwrap().wrap(message);
    if ciphertext_result.is_ok() {
        let ciphertext = ciphertext_result.unwrap();
        for i in 0..ciphertext.len() {
            output_buffer[i] = ciphertext[i];
        }
        return_value = true;
    }
    return return_value;
}

#[no_mangle]
pub extern fn decrypt(message: &[u8], output_buffer: &mut [u8]) -> bool {
    let mut return_value = false;
    let plaintext_result = MESSAGE_WRAPPER.lock().unwrap().unwrap(message);
    if plaintext_result.is_ok() {
        let plaintext = plaintext_result.unwrap();
        for i in 0..plaintext.len() {
            output_buffer[i] = plaintext[i];
        }
        return_value = true;
    }
    return return_value;
}
