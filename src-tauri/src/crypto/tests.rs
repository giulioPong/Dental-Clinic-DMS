use super::*;

const PW: &str = "correct horse battery";
const PW2: &str = "tutt'altra password 42";

fn tp() -> KdfParams { KdfParams { m_kib: 8, t: 2, p: 1 } }
fn fkey() -> [u8; KEY_LEN] { [7u8; KEY_LEN] }
fn data(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }

fn enc(k: &[u8; KEY_LEN], id: &str, d: &[u8], cs: usize) -> (Vec<u8>, EncryptedInfo) {
    let mut out = Vec::new();
    let info = encrypt_stream_with_chunk_size(k, id, d, &mut out, cs).unwrap();
    (out, info)
}
fn dec(k: &[u8; KEY_LEN], id: &str, ct: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decrypt_stream(k, id, ct, &mut out)?;
    Ok(out)
}
fn set_u32(buf: &mut [u8], off: usize, v: u32) { buf[off..off + 4].copy_from_slice(&v.to_le_bytes()); }

// ── vault ──

#[test]
fn vault_roundtrip_e_password_errata() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    assert_eq!(v.meta_bytes.len(), VAULT_META_LEN);
    let k = unlock_vault(&v.meta_bytes, PW).unwrap();
    assert_eq!(k.files_key(), v.keys.files_key());
    assert_eq!(*k.sqlcipher_key_pragma_value(), *v.keys.sqlcipher_key_pragma_value());
    assert!(matches!(unlock_vault(&v.meta_bytes, "password sbagliata"), Err(CryptoError::WrongPasswordOrCorrupted)));
}

#[test]
fn vault_con_parametri_di_default() {
    let v = create_vault(PW).unwrap();
    assert_eq!(parse_vault_meta(&v.meta_bytes).unwrap().params, KdfParams::DEFAULT);
    assert!(unlock_vault(&v.meta_bytes, PW).is_ok());
}

#[test]
fn password_troppo_corta_rifiutata() {
    assert!(matches!(create_vault_with_params("corta", tp()), Err(CryptoError::PasswordTooShort)));
}

#[test]
fn qualsiasi_byte_alterato_in_vault_meta_impedisce_lo_sblocco() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    for i in 0..VAULT_META_LEN {
        let mut m = v.meta_bytes.clone();
        m[i] ^= 0x01;
        assert!(unlock_vault(&m, PW).is_err(), "byte {i} alterato ma sblocco riuscito");
    }
}

#[test]
fn limiti_parametri_argon2_letti_dal_file() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    let try_with = |off: usize, val: u32| {
        let mut m = v.meta_bytes.clone();
        set_u32(&mut m, off, val);
        unlock_vault(&m, PW)
    };
    assert!(matches!(try_with(5, u32::MAX), Err(CryptoError::InvalidMeta(_)))); // memoria enorme
    assert!(matches!(try_with(5, 1), Err(CryptoError::InvalidMeta(_)))); // troppo poca
    assert!(matches!(try_with(9, 1), Err(CryptoError::InvalidMeta(_)))); // t troppo basso
    assert!(matches!(try_with(9, 1000), Err(CryptoError::InvalidMeta(_)))); // t enorme
    assert!(matches!(try_with(13, 64), Err(CryptoError::InvalidMeta(_)))); // p enorme
    assert!(create_vault_with_params(PW, KdfParams { m_kib: 4, t: 2, p: 1 }).is_err());
}

#[test]
fn cambio_password_non_cambia_le_chiavi() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    let (ct, _) = enc(v.keys.files_key(), "doc-1", &data(5000), 4096);

    let new_meta = change_password(&v.meta_bytes, PW, PW2).unwrap();
    assert_ne!(new_meta, v.meta_bytes);
    assert!(unlock_vault(&new_meta, PW).is_err());
    let k2 = unlock_vault(&new_meta, PW2).unwrap();
    assert_eq!(dec(k2.files_key(), "doc-1", &ct).unwrap(), data(5000)); // niente da ricifrare

    assert!(matches!(change_password(&v.meta_bytes, "sbagliata sbagliata", PW2), Err(CryptoError::WrongPasswordOrCorrupted)));
    assert!(matches!(change_password(&v.meta_bytes, PW, "corta"), Err(CryptoError::PasswordTooShort)));
}

#[test]
fn sottochiavi_distinte_e_formato_pragma_sqlcipher() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    assert_ne!(v.keys.files_key(), v.keys.audit_key());
    let p = v.keys.sqlcipher_key_pragma_value();
    assert_eq!(p.len(), 67);
    assert!(p.starts_with("x'") && p.ends_with('\''));
    assert!(p[2..66].chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(&p[2..66], hex(v.keys.files_key()));
}

// ── file .enc ──

#[test]
fn roundtrip_a_confini_di_blocco() {
    for n in [0usize, 1, 4095, 4096, 4097, 8192, 10_000, 3 * 4096] {
        let d = data(n);
        let (ct, info) = enc(&fkey(), "doc-A", &d, 4096);
        assert_eq!(info.size_bytes, n as u64);
        assert_eq!(info.sha256.to_vec(), Sha256::digest(&d).to_vec());
        assert_eq!(dec(&fkey(), "doc-A", &ct).unwrap(), d, "n = {n}");
    }
}

#[test]
fn encrypted_len_coincide_con_la_lunghezza_reale() {
    for n in [0usize, 1, 4095, 4096, 4097, 8192, 10_000] {
        let (ct, _) = enc(&fkey(), "doc-A", &data(n), 4096);
        assert_eq!(ct.len() as u64, encrypted_len(n as u64, 4096), "n = {n}");
    }
}

#[test]
fn roundtrip_con_blocco_di_default() {
    let d = data(2 * DEFAULT_CHUNK_SIZE + DEFAULT_CHUNK_SIZE / 2);
    let mut ct = Vec::new();
    let info = encrypt_stream(&fkey(), "doc-big", &d[..], &mut ct).unwrap();
    assert_eq!(info.size_bytes as usize, d.len());
    assert_eq!(ct.len(), FH_LEN + d.len() + 3 * TAG_LEN);
    assert_eq!(dec(&fkey(), "doc-big", &ct).unwrap(), d);
}

#[test]
fn due_cifrature_dello_stesso_file_sono_diverse_e_senza_testo_in_chiaro() {
    let d = b"RADIOGRAFIA-SEGRETA".repeat(500);
    let (a, _) = enc(&fkey(), "doc-A", &d, 4096);
    let (b, _) = enc(&fkey(), "doc-A", &d, 4096);
    assert_ne!(a, b);
    assert_eq!(&a[0..4], b"DENC");
    assert!(!a.windows(10).any(|w| w == b"RADIOGRAFI"));
}

#[test]
fn chiave_o_document_id_sbagliati_falliscono() {
    let (ct, _) = enc(&fkey(), "doc-A", &data(9000), 4096);
    assert!(matches!(dec(&fkey(), "doc-B", &ct), Err(CryptoError::FileCorrupted)));
    assert!(matches!(dec(&[8u8; KEY_LEN], "doc-A", &ct), Err(CryptoError::FileCorrupted)));
}

#[test]
fn alterazioni_del_file_vengono_rilevate() {
    let (ct, _) = enc(&fkey(), "doc-A", &data(3 * 4096 + 100), 4096);
    let chunk = 4096 + TAG_LEN;

    for pos in [0, 4, 6, 12, 30, FH_LEN + 5, FH_LEN + chunk + 7, ct.len() - 1] {
        let mut m = ct.clone();
        m[pos] ^= 0x01;
        assert!(dec(&fkey(), "doc-A", &m).is_err(), "byte {pos}");
    }
    // troncamento esattamente a un confine di blocco
    assert!(dec(&fkey(), "doc-A", &ct[..FH_LEN + 3 * chunk]).is_err());
    // troncamento a metà blocco, a solo header, a header incompleto
    assert!(dec(&fkey(), "doc-A", &ct[..ct.len() - 5]).is_err());
    assert!(dec(&fkey(), "doc-A", &ct[..FH_LEN]).is_err());
    assert!(matches!(dec(&fkey(), "doc-A", &ct[..10]), Err(CryptoError::InvalidFormat(_))));
    // dati aggiunti in coda
    let mut ext = ct.clone();
    ext.extend_from_slice(&[0u8; 10]);
    assert!(dec(&fkey(), "doc-A", &ext).is_err());
    // blocchi scambiati
    let mut sw = ct.clone();
    let (a, b) = (FH_LEN, FH_LEN + chunk);
    for i in 0..chunk {
        sw.swap(a + i, b + i);
    }
    assert!(dec(&fkey(), "doc-A", &sw).is_err());
}

#[test]
fn verify_encrypted_file_len_su_file_reali() {
    let dir = std::env::temp_dir().join(format!("crypto-len-{}", hex(&data(4)[..4]) + &std::process::id().to_string()));
    std::fs::create_dir_all(&dir).unwrap();
    let (ct, _) = enc(&fkey(), "doc-A", &data(10_000), 4096);
    let p = dir.join("a.enc");
    std::fs::write(&p, &ct).unwrap();
    assert!(verify_encrypted_file_len(&p, 10_000).is_ok());
    assert!(matches!(verify_encrypted_file_len(&p, 10_001), Err(CryptoError::SizeMismatch { .. })));
    std::fs::write(&p, &ct[..ct.len() - 1]).unwrap();
    assert!(matches!(verify_encrypted_file_len(&p, 10_000), Err(CryptoError::SizeMismatch { .. })));
    std::fs::write(&p, &ct[..10]).unwrap();
    assert!(matches!(verify_encrypted_file_len(&p, 10_000), Err(CryptoError::InvalidFormat(_))));
    std::fs::write(&p, b"questo non e' un file cifrato, ma e' abbastanza lungo").unwrap();
    assert!(matches!(verify_encrypted_file_len(&p, 10), Err(CryptoError::InvalidFormat(_))));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn dimensione_blocco_nel_header_validata() {
    let (ct, _) = enc(&fkey(), "doc-A", &data(100), 4096);
    for v in [1u32, 100, u32::MAX] {
        let mut m = ct.clone();
        set_u32(&mut m, 5, v);
        assert!(matches!(dec(&fkey(), "doc-A", &m), Err(CryptoError::InvalidFormat(_))), "cs = {v}");
    }
}

#[test]
fn decrypt_to_vec_rispetta_il_limite_e_non_restituisce_dati_parziali() {
    let d = data(10_000);
    let (ct, _) = enc(&fkey(), "doc-A", &d, 4096);
    let ok = decrypt_to_vec(&fkey(), "doc-A", &ct[..], 20_000, d.len()).unwrap();
    assert_eq!(&ok[..], &d[..]);
    assert!(matches!(decrypt_to_vec(&fkey(), "doc-A", &ct[..], 5_000, 0), Err(CryptoError::TooLarge)));
    assert!(matches!(decrypt_to_vec(&fkey(), "doc-B", &ct[..], 20_000, 0), Err(CryptoError::FileCorrupted)));
}

// ── KeyStore ──

#[test]
fn keystore_lock_unlock() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    let ks = KeyStore::new(Duration::from_secs(60));
    assert!(matches!(ks.keys(), Err(CryptoError::Locked)));
    ks.unlock(v.keys.clone());
    assert!(ks.is_unlocked());
    assert_eq!(ks.keys().unwrap().files_key(), v.keys.files_key());
    ks.lock();
    assert!(!ks.is_unlocked());
    assert!(matches!(ks.keys(), Err(CryptoError::Locked)));
}

#[test]
fn keystore_blocco_per_inattivita_e_attivita_che_rinvia_il_blocco() {
    let v = create_vault_with_params(PW, tp()).unwrap();
    let ks = KeyStore::new(Duration::from_millis(400));
    ks.unlock(v.keys.clone());
    std::thread::sleep(Duration::from_millis(250));
    assert!(ks.keys().is_ok()); // attività: azzera il timer
    std::thread::sleep(Duration::from_millis(250));
    assert!(ks.keys().is_ok()); // 250 ms dall'ultima attività, non 500
    std::thread::sleep(Duration::from_millis(600));
    assert!(ks.expire_if_idle()); // il thread di fondo blocca anche senza richieste
    assert!(matches!(ks.keys(), Err(CryptoError::Locked)));
    assert!(!ks.expire_if_idle());
}
