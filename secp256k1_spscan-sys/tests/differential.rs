// Self-contained vector test for the relocated/renamed `secp256k1_spscan-sys` byte-FFI.
//
// Pins fixed deterministic inputs (one scan key, 33 tweaks, 2 spend points) and
// asserts that `scan_spend_points` / `scan_spend_points_batch` reproduce the
// HARDCODED expected x-only candidate bytes below. We exercise a few shapes:
// 1 tweak x 1 spend, 5 tweaks x 2 spends, 33 tweaks x 2 spends, and check that
// the per-tweak and batched paths agree with each other and with the vectors.
//
// The expected values were captured once from the byte-identical secp256k1 fork
// this crate was relocated from (whose SP-scan kernels are BIP352-vector
// verified). The fork is now deleted; this test has no dependency on it.

// Fixed scan key (raw 32-byte secret).
const SCAN_HEX: &str = "42aa000000000000000000000000000000000000000000000000000000000001";

// 33 fixed tweak points (compressed 33-byte pubkeys), in order.
const TWEAKS_HEX: [&str; 33] = [
    "025e2bd2b98d85245fe042d042938708d3f9fa4402f56054f11f2874b40c0235b1",
    "023a3ef10f66371a41244f9de1bbd902307cb99acf98e3328d3bf036d0ad75c9a8",
    "03309920230e4bf8b404a530b4941bac2819f031205ae8423daf4b2853db49f152",
    "027bb9cec9086b43cea2cdb508e7162c7f1d97647bb403e9c727b40c883cfb8873",
    "026a94b87e7f2924c1be9498223d82cd6207369195a57f33f3104cde279d94ef67",
    "0239f8dd4366ef2a769adf7da0622547ae90bf8ef097da642430e91c3e4e298fb9",
    "0217bc0cdde2ddd2aba7c5abf15f3319e2750c8cea0b3a59691e73131fb7186283",
    "02737e93029d0e97f2ffce952d045f2b997312c439dd44f9fc3444f52600d1dba1",
    "03977b8e9fc5cee3808f8f36e3368d6a90ca5188f9aa04c6b69e63f2dc67318489",
    "020dbc54a7c24d79e17ca43d021b3a097cddcc38a657da5c4b77ddd19bb9a50fe7",
    "0362a632640baf2beaf8d3e4670fec64d373a674bebd59a14fd7b49c07604e3410",
    "021bd2075e3b110ec0de0c80324f0cb6fdb53e750adfe001288a547191f97da6f1",
    "02dfdb251c8e6a96361dc4c7aefff4032c9e14bbf93da0dff4fe42408df34db158",
    "03931549baf42aa5d1e3fc30160103166af7716d03cec0bfc9cf56bf970da94232",
    "025dee4b570fe50b0c907b5c9fb322852e1eb07869439d7bb977d8eb6986aacd5e",
    "03f310be6b9f12bcdbe1bdd5afb0a190b50a0b3f0e56c6809edc6a8de75b19bbc3",
    "023fe1bb8e0c691747fc6c334c89ddcc442f9e10b4be5010cf659dccd880c05386",
    "02fd3dc1b411e5e525a2037fc1053540cc620d0f2984fe67a488970ca767dac69c",
    "03ba162a1bf7386cbdf52042a0fe6bc5f42ca64e34521b8a9ff39455ef43d08450",
    "02ab3c5a15569e925b77571d275feb758998b3ddb904db200cbb2b2658b5ca6900",
    "03f9d1c35eb4caddb13538c9cbbb47270e35baa80d29dcd7247691a7eb61b2dc97",
    "024f1f84561cdbeca66580c726918ab014d4ee27de2fb50cb58bcee9873d8682a0",
    "03e3ce6b4ac0be7b0d9010644bfd80665fae2e21b0218f481428fa2dabbfb81a22",
    "0361406ce56c8ee959ae408d8dcf20d9a29516e27babf44edd922b77532ac575c0",
    "03086c9f9f1f7ad511fa1d775c93bb4e7ed56bfb4244c4d7561fdb54685857c1c7",
    "02dfed2f0c35aaecbd7f39b9ac19c8dc0492e214457d868471d63e38dd34c2f14e",
    "03d922eac2e1792362db6552c9ee517c47abf22f9d6cb23b458544a0213b675d25",
    "02c933e228db2750560fb2a855aa8057bc99d6bfd30d830fdb4d6ad03cb63cc05d",
    "0319bc481579761e346fb20958a8d1437fc61257efdd5e4c8827a765e3f8cdb5ec",
    "02b75d6506caf344349e95f264259f0c2c38bf56049762ece1263da609a5303c97",
    "02f7c49ff3afec448c2da85351abb9a4a91a6cb0d8dac009a45d59a0505e6d0d4f",
    "0367beeebe50618b182b578058cd3ecadee931e3b1df144255ec107b49d4bb0731",
    "0256b3db1dd82046bf20adc4302929526aeab0b394efb95674e3a2b1090ec55a6b",
];

// 2 fixed spend points (compressed 33-byte pubkeys).
const SPENDS_HEX: [&str; 2] = [
    "0260cae9de7a7ab02e6193c2fda512494063774d2e6ffda9ade78b7ed81bb159cd",
    "0263b3a0acebf2fbad8b3ddb904430512e4634efdb00049557cd95c52b4b1412d6",
];

// Expected x-only candidates for ALL 33 tweaks x 2 spend points, grouped by
// tweak (outer index = tweak, inner = spend point), flattened row-major:
// EXPECTED[2*t + s] is the candidate for tweak t, spend point s.
const EXPECTED_HEX: [&str; 66] = [
    "3f17c3ddd35236b2f5d7717d8e433ac1537c8ee4c0da28a386809010316870db",
    "5221ffbea8fba1bc7234f4082f968c729a7691179db4148bf62548eddb66ff6e",
    "59cf5b3f670bb1575a7227043539e8076d6805015ca68db0294d5db3aad39a6b",
    "8628fb54e697949e2aae2576bcb293e8dd1bd60af49a0688e04de838099cebaa",
    "36161c82ab50362fa03261e4405194625e32cd4dacd31e98926b6511ac1d3403",
    "30585d0ff446cc33e0381b70d73cd510eee2b31dd3d5b344a92cc1f815b32ae5",
    "f0593b22bede7bf1216865693138ded53f79feab08b0326d941ccb2c984683e7",
    "e6c58b0b8103464fbee2fe26adc3085b3555c5a6b6fdd608763de0338606a310",
    "24d96053c96168d4380f7b0f4a8d03d6f7452d11c9feb27bb8570accb47b142e",
    "2597cacbeabe31c2621621f227061385d0bf73415ce85536bac010bba1180502",
    "361d0992bbe3637c665eee6d2767ad9daf92f4b52b881f67950a1f7a5b3fd1a8",
    "78897775e1f0908a40587efd33814f91728500af6e222687f783b61a77932c04",
    "a86014e958f43fba0315a0f13481c5ae3f20dd9c56e3b51ce662f145134e3e26",
    "7fec848c2c7986a94eb35436a3e7a8af3414ae432184685a3cbbb3b28a9b9919",
    "6460e802528dbd0a837d605767791ef42ba2fd8abed1cb7bf5e6f4566630d3ac",
    "6c83999aeebd35beca933cc2c087c005984fbdb080c798ff2addaa893843ce43",
    "7ac5fae7d6899766da1b9e50d0c78f76a157422d281a226a6177d044cd7d717a",
    "3ab4f8ab9e284adb16ba79b27f9a13414e1e204508d01f813908b35117ae6938",
    "70570378d679e83172e56efff3fec9b3d3337eb843f7353c344e277903eddb48",
    "1840654df7f9f7aa4c30deb7fe9a6ba0a8b476d580c7c192accdef6f118a7cfd",
    "f4b54805168164bad42c116386fa1d491e472ce291be620c50d709b88319e950",
    "d3350f2c784dc87f89e2697482a613a57e8f6db339e13afbd4391180591cb989",
    "ef45dc7f765f06bab7bef32cb791719640c79ffd22ff7eaf978142234470263e",
    "f9e5f1ebb2b66b1eac9f510e6106594b452d5743a58494703d23a5624bef5000",
    "eb3fefc6d77bca08bb8059e4cc8a5c9c18b8757f57efcf06d4f611193b65cc7c",
    "542a97f242880ee4b90cea5bc41eda201d09da1b223c03e5f3ea4dca88069fe7",
    "3611efdc2dafc76e1afaf8339bd7a2bdc1e05bb1e35d222bd05ca7606662f948",
    "c4d747674f47f696b9ac1fd3441ff001c20e24faa2b76b537b7acaca4ad9bdec",
    "d21c24f177108cf0ec70c74b83868307167ab178d915ef65a69ba88cc4b9b93a",
    "dd09df8c1c18e27276be0c94860ac501f36cba4559f41b64ffe89bbd9c8505ad",
    "87b41a76b42c955e36f4968b0ab33b46bc0bd1d1eeed1fa469084c7aad305539",
    "c7e861d4b5cfa9cf045abee718b5e97a965e7305029cbcd595084fff84cc0de7",
    "6545647205d4cf49cc2a4c3c5bcc8a791d7e36e76d532634f73c3a7d02a16583",
    "af47f9e6086fb4294a7700459ae01bb483ea41e85ad807ba9fe784cb3e6e0535",
    "fdbdf7c2f4c22d61e0373c50003d4848264eaded6030221b8efb1bfeb9ec2dd5",
    "719ec437f160a1b31919315428a899bf19ac88ba5bc3ea10877bbb529ed5552b",
    "5bbc648320efddb9c89e853ee2efd1512dfa423cc7f25db0b87869530765a2d5",
    "6915eb9410d2cebacf65ce5a69b4937ee3a26447d23f05518bf4934a5f92ee12",
    "801685a00171a5afcbb02db612a665dd766c742013c2496a9eb46560b135ae19",
    "cba32667792c588d2d2bffbc9ac5be706c7d2a9578ef0642d4040ec3170fcf03",
    "6e3ed614b5d72845d66f71c79c03adb36bc262bdc5171f1629c8b9ed36c97e1f",
    "c9c11e4e143e7472c8950df2cc6ff0e7977992c07e334b0d865017bf12a20844",
    "d3a3388691977a7287a129d1d441ca54a245529a93713a38ccfa3aba714ba93e",
    "feafdbfa87b8bfd970305692638739492811129e24b57d8a1f94147142385565",
    "dbee96c35b70338509e1cafe4fc725bbaa8482f0309699d9e7976d3c2a9ee242",
    "c28e49e12eae32a7e96727e423b05acef07cd0ab20c6823e8a9c1e8dc9dca9af",
    "4b57ec5dff221a858df6a46e9592cd19edf0fde808f2ab790a6d71f980c04e7e",
    "6b0e9b0b4f5e81d93ad0a6ee612147c4e70c467afe646d124973b715ae369254",
    "f3937e6626bc5531ace33ec840dbfee2d37c063bb5406382048ea489391452c0",
    "0a4973f5d2ba5144604d0f7b1425d516c04145cb0025a1be6b3f411495cbfbdf",
    "7ee1bd6ddda5cb5b28e9137e59fc6c957b1e3901342992dd90126a5bd0418879",
    "340c495de287e7ed0f5ea82fcfe5c7a9c091a18bfd7f277656c53587bf0b58ac",
    "c1eb54a0f417ac1590d9131f40ccd47ec8f4f194009e49dc3b52b35286063052",
    "7142b2fe65f7a621a86a73ab8a32b8c182165b2f1605d63b2bdae845e3031a39",
    "6d5648607f9c4081aca42173263309098e9de177346e05039c0fe47115a7d24e",
    "e94f84fd58a7e161a04ccc8a44b8099fc20b7752052614ee557200c6b30e8ee6",
    "5fc5d60d8483a1db2189c47d8c49206edce112cb11aa236fd441e4abc1dc6a03",
    "0acf8ce24b460bb4152416982d168dc941da8b5310cc93ce1fdaea5b0ae76a27",
    "dbb472e446fd07e61a6f4762ba6a4dcc45e31dfd8f975282366cbc29bd6292f3",
    "3c50cde4f3bd2b986bc488a3d87e3354ff55a4dd8554fd9ba68768b536884152",
    "1db52d776006a71cd394293b421c27461170aff03a5ff269279160eb862d96fe",
    "a304ee422d7694d78453b03aca60ac25e4d7b03882a7072c77ebdcc582b7c787",
    "3f23bb4b46a30786e17c006ada32156b39ead95b0db99822f942a49397fb788e",
    "953ca80fe2938edc98ae6e01de48e3e12552e8d3ca7b0df01871dd10b3f47882",
    "fd3ec95e1689ae42f8f2bb5aaa472a37ee3a3526461b8fed635713e57926ca1e",
    "bb6ae479e898fd515b6d93963fd016de6dd3843e05e88ebf919d1e94f5619068",
];

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert_eq!(s.len(), 64, "expected 32-byte hex");
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex");
    }
    out
}

fn unhex33(s: &str) -> [u8; 33] {
    let mut out = [0u8; 33];
    assert_eq!(s.len(), 66, "expected 33-byte hex");
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex");
    }
    out
}

fn scan() -> [u8; 32] {
    unhex32(SCAN_HEX)
}

fn tweaks() -> Vec<[u8; 33]> {
    TWEAKS_HEX.iter().map(|s| unhex33(s)).collect()
}

fn spends() -> Vec<[u8; 33]> {
    SPENDS_HEX.iter().map(|s| unhex33(s)).collect()
}

// Expected candidate for tweak t, spend s (n_spend in {1, 2}).
fn expected(t: usize, s: usize) -> [u8; 32] {
    unhex32(EXPECTED_HEX[2 * t + s])
}

#[test]
fn vectors_1_tweak_1_spend() {
    let scan = scan();
    let tweaks = tweaks();
    let spends = spends();

    let per = secp256k1_spscan_sys::scan_spend_points(&scan, &tweaks[0], &spends[..1]).unwrap();
    assert_eq!(per.len(), 1);
    assert_eq!(per[0], expected(0, 0));

    let bat =
        secp256k1_spscan_sys::scan_spend_points_batch(&scan, &tweaks[..1], &spends[..1]).unwrap();
    assert_eq!(bat.len(), 1);
    assert_eq!(bat[0], expected(0, 0));
}

#[test]
fn vectors_5_tweaks_2_spends() {
    let scan = scan();
    let tweaks = tweaks();
    let spends = spends();
    let n_tweaks = 5;
    let n_spend = 2;

    // Per-tweak path == vectors.
    for t in 0..n_tweaks {
        let per =
            secp256k1_spscan_sys::scan_spend_points(&scan, &tweaks[t], &spends[..n_spend]).unwrap();
        assert_eq!(per.len(), n_spend);
        for s in 0..n_spend {
            assert_eq!(per[s], expected(t, s), "per-tweak mismatch at t={t} s={s}");
        }
    }

    // Batch path == vectors; flat, row-major by tweak.
    let bat = secp256k1_spscan_sys::scan_spend_points_batch(
        &scan,
        &tweaks[..n_tweaks],
        &spends[..n_spend],
    )
    .unwrap();
    assert_eq!(bat.len(), n_tweaks * n_spend);
    for t in 0..n_tweaks {
        for s in 0..n_spend {
            assert_eq!(
                bat[t * n_spend + s],
                expected(t, s),
                "batch mismatch at t={t} s={s}"
            );
        }
    }
}

#[test]
fn vectors_33_tweaks_2_spends() {
    let scan = scan();
    let tweaks = tweaks();
    let spends = spends();
    let n_tweaks = 33;
    let n_spend = 2;

    let bat = secp256k1_spscan_sys::scan_spend_points_batch(
        &scan,
        &tweaks[..n_tweaks],
        &spends[..n_spend],
    )
    .unwrap();
    assert_eq!(bat.len(), n_tweaks * n_spend);

    let mut per_all: Vec<Vec<[u8; 32]>> = Vec::with_capacity(n_tweaks);
    for t in 0..n_tweaks {
        let per =
            secp256k1_spscan_sys::scan_spend_points(&scan, &tweaks[t], &spends[..n_spend]).unwrap();
        per_all.push(per);
    }

    for t in 0..n_tweaks {
        assert_eq!(per_all[t].len(), n_spend);
        for s in 0..n_spend {
            let want = expected(t, s);
            assert_eq!(bat[t * n_spend + s], want, "batch mismatch at t={t} s={s}");
            assert_eq!(per_all[t][s], want, "per-tweak mismatch at t={t} s={s}");
        }
    }
}

#[test]
fn accepts_more_than_64_spends() {
    let scan = scan();
    let tweaks = tweaks();
    let base_spends = spends();
    let spends = (0..65)
        .map(|i| base_spends[i % base_spends.len()])
        .collect::<Vec<_>>();

    let per = secp256k1_spscan_sys::scan_spend_points(&scan, &tweaks[0], &spends).unwrap();
    let bat = secp256k1_spscan_sys::scan_spend_points_batch(&scan, &tweaks[..1], &spends).unwrap();

    assert_eq!(per.len(), 65);
    assert_eq!(bat, per);
}
