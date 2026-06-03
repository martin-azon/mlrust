//! NTT constants for the ML-KEM modulus q = 3329.
//!
//! The tables in this module follow the FIPS 203 Appendix A exponent order,
//! but their entries are stored in Montgomery representation.


/// FIPS 203 Appendix A zeta table converted to Montgomery representation.
/// Each entry is:
///
/// ```text
/// zeta^BitRev_7(i) * R mod q,
/// ```
///
/// where:
/// q = 3329
/// R mod q = 2285
/// zeta = 17
pub const FIPS_ZETAS_MONT: [i32; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
    3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199,
    2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
    516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
    2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];


/// FIPS 203 Appendix A base-multiplication zeta table converted to
/// Montgomery representation.
///
/// Each entry is:
///
/// ```text
/// zeta^(2*BitRev_7(i) + 1) * R mod q.
/// ```
pub const FIPS_BASEMUL_ZETAS_MONT: [i32; 128] = [
    2226, 1103, 430, 2899, 555, 2774, 843, 2486,
    2078, 1251, 871, 2458, 1550, 1779, 105, 3224,
    422, 2907, 587, 2742, 177, 3152, 3094, 235,
    3038, 291, 2869, 460, 1574, 1755, 1653, 1676,
    3083, 246, 778, 2551, 1159, 2170, 3182, 147,
    2552, 777, 1483, 1846, 2727, 602, 1119, 2210,
    1739, 1590, 644, 2685, 2457, 872, 349, 2980,
    418, 2911, 329, 3000, 3173, 156, 3254, 75,
    817, 2512, 1097, 2232, 603, 2726, 610, 2719,
    1322, 2007, 2044, 1285, 1864, 1465, 384, 2945,
    2114, 1215, 3193, 136, 1218, 2111, 1994, 1335,
    2455, 874, 220, 3109, 2142, 1187, 1670, 1659,
    2144, 1185, 1799, 1530, 2051, 1278, 794, 2535,
    1819, 1510, 2475, 854, 2459, 870, 478, 2851,
    3221, 108, 3021, 308, 996, 2333, 991, 2338,
    958, 2371, 1869, 1460, 1522, 1807, 1628, 1701,
];


/// Final scaling factor converted to Montgomery representation.
/// This is 128^(-1) * 2285 mod 3329 = 512
pub const INV_NTT_SCALE_MONT: i32 = 512;


#[cfg(test)]
mod tests {
    use super::*;

    const Q: i32 = 3_329;
    const ZETA: i32 = 17;
    const R_MOD_Q: i32 = 2_285;

    fn bitrev7(x: usize) -> usize {
        let mut y = 0usize;

        for i in 0..7 {
            y <<= 1;
            y |= (x >> i) & 1;
        }

        y
    }

    fn mod_pow(base: i32, exp: usize) -> i32 {
        let mut result = 1i64;
        let mut base = (base as i64).rem_euclid(Q as i64);
        let mut exp = exp;

        while exp > 0 {
            if exp & 1 == 1 {
                result = (result * base).rem_euclid(Q as i64);
            }

            base = (base * base).rem_euclid(Q as i64);
            exp >>= 1;
        }

        result as i32
    }

    fn mont_encode(x: i32) -> i32 {
        ((x as i64) * (R_MOD_Q as i64)).rem_euclid(Q as i64) as i32
    }

    #[test]
    fn inv_ntt_scale_mont_is_correct() {
        let inv_128 = 3303;
        let expected = mont_encode(inv_128);

        assert_eq!(INV_NTT_SCALE_MONT, expected);
        assert_eq!(INV_NTT_SCALE_MONT, 512);
    }

    #[test]
    fn fips_zetas_mont_match_formula() {
        for i in 0..128 {
            let exponent = bitrev7(i);
            let zeta = mod_pow(ZETA, exponent);
            let expected = mont_encode(zeta);

            assert_eq!(
                FIPS_ZETAS_MONT[i],
                expected,
                "wrong FIPS_ZETAS_MONT[{i}], exponent = {exponent}"
            );
        }
    }

    #[test]
    fn fips_basemul_zetas_mont_match_formula() {
        for i in 0..128 {
            let exponent = 2 * bitrev7(i) + 1;
            let zeta = mod_pow(ZETA, exponent);
            let expected = mont_encode(zeta);

            assert_eq!(
                FIPS_BASEMUL_ZETAS_MONT[i],
                expected,
                "wrong FIPS_BASEMUL_ZETAS_MONT[{i}], exponent = {exponent}"
            );
        }
    }

    #[test]
    fn bitrev7_known_values() {
        assert_eq!(bitrev7(0), 0);
        assert_eq!(bitrev7(1), 64);
        assert_eq!(bitrev7(2), 32);
        assert_eq!(bitrev7(3), 96);
        assert_eq!(bitrev7(64), 1);
        assert_eq!(bitrev7(127), 127);
    }
}