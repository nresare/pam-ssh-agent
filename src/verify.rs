#[cfg(feature = "native-crypto")]
use crate::nativecrypto::PublicKeyVerifier;
#[cfg(not(feature = "native-crypto"))]
use signature::Verifier;
use ssh_key::public::KeyData;
use ssh_key::Signature;

pub fn verify(
    key_data: &KeyData,
    message: &[u8],
    signature: &Signature,
) -> Result<(), signature::Error> {
    key_data.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use crate::verify::verify;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use ssh_encoding::Decode;
    use ssh_key::{PublicKey, Signature};

    #[test]
    fn test_verify_ecdsa_p256() -> anyhow::Result<()> {
        do_verify(
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK\
            gm6hassh04KocJTsu4QEMw5GRVeWR/oi9QyCZ04r3tFSYhi7GI+lJBD5WV4LSp9MOJu2WACpWjowZdeAXS\
            9uw=",
            &BASE64_STANDARD.decode(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIEC3hAQv1h3PZ1xUUGjdwr27LJBDjxM6Z7suD\
                YAs/UIJAAAAIQC/TxC6dG/eLiv7LhMkR7SctUAc+OMGXqdHCgoMd5x+nQ==",
            )?,
        )
    }

    #[test]
    fn test_verify_ecdsa_p384() -> anyhow::Result<()> {
        do_verify(
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBA\
            ZXH05QZ3EuWZuqOmHSeGk1BwwVWwkFJ+IPwIsxi1sVCerp0Zjb4nPpKTgtN8rAyC4rTdpJnwzDnvVJ8L0j\
            IABqKuWws6UShmL/W/mfpCV8sKITlEIXhkbtErHQ4StxHg==",
            &BASE64_STANDARD.decode(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABpAAAAMQCg8/DrnRuxviXd6mnPFB3dtBc/HCWJfmD3h\
                aj5mxno0q9l36JAYro8OEwKauJ4llcAAAAwDfEr+CVBS5xcey4N4+QiHYr6ch7mavMIaqX/xZHjWuI\
                GXd1+yrxaxp4zOI0ztbLT",
            )?,
        )
    }

    #[test]
    fn test_verify_ecdsa_p521() -> anyhow::Result<()> {
        do_verify(
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBA\
            GWA+tCu8dqObykPnhsDj6riqGmNZnM0Ie/+xpICTRO9Zju8b76b7VNp/8q9QZ7nP91YITxDr4k21TUPZ9A\
            w1/CvADphX0THL9ADDtq8yo79Vxmw0MfATwarBDWA8YBe9i+KST1X/89tNemL4JR8IbMwXlmz6Vxl0Xt1G\
            pte0BH5QA4mg==",
            &BASE64_STANDARD.decode(
                "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAACLAAAAQgCQQ7Pl5ZQoPco1J6dwGR5s8pSnA2tCBd/x8\
                pWJIMsE5HUI/mLnFmAwi7dedk2KsHqGFVrh7CuIJcxrfGvc6Opr2gAAAEEy9ET09sbYvGqSGsmG87e\
                lqtIfh1wUjJEffRx96k3CwMw+uihtUMTBnoi2xoxT4VvYGd5ARdo6RDD3MtJ575TFzQ==",
            )?,
        )
    }

    #[test]
    fn test_verify_ed25519() -> anyhow::Result<()> {
        do_verify(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn3H5p6CReDJp0cZ+nfzsqQ7jvuQz17pBBeyN\
            G1syjC",
            &BASE64_STANDARD.decode(
                "AAAAC3NzaC1lZDI1NTE5AAAAQFaLbFzI92QL1auhVfZE354hfY+HOYcWkAbUqYLXQmqUBCWP4D12i\
                zSmXQjtfs8hGHPJolPjfjqgqFgj3Aly/wE=",
            )?,
        )
    }

    #[test]
    fn test_verify_rsa_with_sha512() -> anyhow::Result<()> {
        do_verify(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnehvLShDK8zLaLNEtnZXfeS+U8WgnUp+cwP/6/\
            MHc9/FJTC4XIOkhUjeD2tQW6ISD51r31cWP5mYl5R4XSoHbgTa7kPOjAilUmojx/KIUu3306XUfi71qTWaCI0\
            kPz40YWkQiYQXO8krhPkJaZKThlD8T3W637aV5c+uWmI2bhvlAvSdKcLeG59YcRsgpJHixEmBoAYiGDJmv8tH\
            6M18GFsSuKw51jmAT6yRO+GrWA7uW3UsMWArZZoXTwLbOEw3XALpJrP67qjSlaStoNwClPomwhin6rnDD5z+w\
            JClVn8m0l29oIINJCuZqwpBz0rKyONo9ptDIGh9bRc6oYSLPj9SzZbLqUZvC2Axw5v4YzAgKD3uSC7z4g5gYI\
            coqQNqO5g2/dlDm6py5bLC7sVKwWedxpFm1bB/1vmAvstaKbxkRwhcAzrLF5dTYq+1aUk6JGqWGSi8s5zdf2u\
            j85Bh4a0rDESBnUODQWQFgAmzf1q/uEqNqI/mHJU29dM3Wir8=",
            &BASE64_STANDARD.decode(
            "AAAADHJzYS1zaGEyLTUxMgAAAYBaehPjXOehIg2wOHa0a+u4g91oyZ8NgX7Mibgnkrdf+FB8KWCWKL8zIACp\
            AjSnAo0UXQb1etfpROAS8zqTUnONUi3Hs852rOaiNLWQcxhMeszMCbLrY5JaXRWhmm92nsBXNRkgrLvaH1fJ0\
            d7NlaXYHjI4E/v2jwUVOIb4trI55mJFB2l6jPjmlwRY+wchh6xJ5HmRbY7mJ2ypcsunuxlSj9XUKV2ABVdG+V\
            WdkXw4SWDx8Eqs4FoF4axrlsPcrhKK2dy1sSWyjN0YfAZPILO7brdsgJURIMGXE1UYJvCEHvgT3MpmBZUD/av\
            IXG/H1kdaAHa5fmH791msc26DwrVJqlZG8A5hoTrZpiNEZnumPHmLB5E/yQxqlokHtajIkvEttu1jk9CJRizm\
            Xtw/Fbx+SBAbP+f2Hw27N0lPTH2YaAg8Uic0XkLUyO3FVD/abmR0vv+8nsOEdAHTFQxlK4Y+Vl6nld6Tepe/Z\
            f4suG0T1HWqHECBscaam+nx3yJzMh8="
            )?,
        )
    }

    #[test]
    fn test_verify_rsa_with_sha256() -> anyhow::Result<()> {
        do_verify(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDoyyCsYlloNmxjZBNbeQdYv6vrpPoaTuQFWPXgo\
            cZfhvHvDumiYUEC/wlv47q4SVi0Uh4o7qE8914NXjW6q0iu7yr0yn8RcAPQZldQ6ho3GwzZ/5ojolFkgRWxUa\
            txMzwk0e7GmiHbPaIZ3qZlaD4X+k4YviQQ1GLvutegvUXB8aT1SwICf/0aYICZV1u1+Ymu1A5rvBiO5Is4pQ6\
            40AG5rA1cTFBUA/8VzogXT+7UQowzj5T0sxzpNEFyUIDQcD02Si1/O8c054Ztzbkyd0CgJVyul4/OOQBv08Le\
            tD0lQT32iqiQbLe9GJwI3ubWJ51qyEnjUlGkUzn4sAV1Skfb",
            &BASE64_STANDARD.decode(
                "AAAADHJzYS1zaGEyLTI1NgAAAQCZd3rHyxoZ42KdB73ZW+wKYTKDCZwogbBkRkyjwUZQro+/b+lj4D2r\
                3lsbQW6Ynh/q6Y97jt6dtUbIq3bXdhLqh+pmLWnqAWY+8s5lSOXi9q8UiCCzerKFNspjvHN2iCTDYalVo\
                pTacrzcN0VyT1BMXZRdQqsG9VohSbBJhl+g/z9vfC00M/zgrZ+qIgjESO/F+ER4od/niwACdTj53VsiHW\
                SZlApcMpNM3kLjwRBD6dKFkJa/ZPMWMHj+CoQx9yamJGTZUAXMGSoxu5SBD39bXZ+26giwx7nOAO15UMz\
                qKSv2bTWqYPrl4emlwL95cj7eGUvs4+v5p9LGyHqLvZfp",
            )?,
        )
    }

    fn do_verify(pubkey: &str, sig_bytes: &[u8]) -> anyhow::Result<()> {
        let key = PublicKey::from_openssh(pubkey)?;
        let mut sig_reader = sig_bytes;
        let sig = Signature::decode(&mut sig_reader)?;
        let key_data = key.key_data();
        // this should not fail
        verify(key_data, b"challenge", &sig)?;
        // this should fail as the message to be signed is different
        assert!(verify(key_data, b"something_else", &sig).is_err());

        // let's flip the last byte of the signature around and make sure that
        // the verification fails
        let mut buf = sig_bytes.to_vec();
        let len = buf.len();
        buf[len - 1] = !buf[len - 1];
        let mut sig_reader = buf.as_slice();
        let sig = Signature::decode(&mut sig_reader)?;
        assert!(verify(key_data, b"challenge", &sig).is_err());

        Ok(())
    }
}
