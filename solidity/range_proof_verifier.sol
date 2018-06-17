pragma solidity ^0.4.19;
pragma experimental ABIEncoderV2;

library alt_bn128 {

    uint256 public constant q = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // curve order
    uint256 public constant n = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // prime field order
    
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    function add(G1Point p1, G1Point p2) internal view returns (G1Point r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        assembly {
            if iszero(staticcall(not(0), 6, input, 0x80, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function mul(G1Point p, uint256 s) internal view returns (G1Point r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        assembly {
            if iszero(staticcall(not(0), 7, input, 0x60, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function neg(G1Point p) internal returns (G1Point) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, n - (p.Y % n));
    }

    function eq(G1Point p1, G1Point p2) internal pure returns (bool) {
        return p1.X == p2.X && p1.Y == p2.Y;
    }

    function add(uint256 x, uint256 y) internal pure returns (uint256) {
        return addmod(x, y, q);
    }

    function mul(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulmod(x, y, q);
    }

    function inv(uint256 x) internal view returns (uint256) {
        return exp(x, q - 2);
    }

    function mod(uint256 x) internal pure returns (uint256) {
        return x % q;
    }

    function sub(uint256 x, uint256 y) internal pure returns (uint256) {
        return x >= y ? x - y : q - y + x;
    }

    function neg(uint256 x) internal pure returns (uint256) {
        return q - x;
    }

    function exp(uint256 base, uint256 exponent) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory output;
        input[0] = 0x20;  // length_of_BASE
        input[1] = 0x20;  // length_of_EXPONENT
        input[2] = 0x20;  // length_of_MODULUS
        input[3] = base;
        input[4] = exponent;
        input[5] = q;
        assembly {
            if iszero(staticcall(not(0), 5, input, 0xc0, output, 0x20)) {
                revert(0, 0)
            }
        }
        return output[0];
    }
}

contract EfficientInnerProductVerifier {
    using alt_bn128 for uint256;
    using alt_bn128 for alt_bn128.G1Point;

    uint256 public constant m = 4;
    uint256 public constant n = 2;

    alt_bn128.G1Point[m] public gs;
    alt_bn128.G1Point[m] public hs;
    alt_bn128.G1Point public H;

    function EfficientInnerProductVerifier(
        uint256 H_x,
        uint256 H_y,
        uint256[2 * m] gs_coords,
        uint256[2 * m] hs_coords
    ) public {
        H = alt_bn128.G1Point(H_x, H_y);
        for (uint8 i = 0; i < m; i++) {
            gs[i] = alt_bn128.G1Point(gs_coords[i], gs_coords[m + i]);
            hs[i] = alt_bn128.G1Point(hs_coords[i], hs_coords[m + i]);
        }
    }

    struct Board {
        alt_bn128.G1Point[m] hs;
        alt_bn128.G1Point H;

        alt_bn128.G1Point c;
        alt_bn128.G1Point l;
        alt_bn128.G1Point r;
        uint256 x;
        uint256 xInv;
        uint256[n] challenges;
        uint256[m] otherExponents;
        alt_bn128.G1Point g;
        alt_bn128.G1Point h;
        uint256 prod;
        alt_bn128.G1Point cProof;
        bool[m] bitSet;
        uint256 z;
    }

    function verify(
        uint256 c_x,
        uint256 c_y,
        uint256[n] ls_x,
        uint256[n] ls_y,
        uint256[n] rs_x,
        uint256[n] rs_y,
        uint256 A,
        uint256 B
    ) external view returns (bool) {
        return verifyWithCustomParams(alt_bn128.G1Point(c_x, c_y), ls_x, ls_y, rs_x, rs_y, A, B, hs, H);
    }

    function verifyWithCustomParams(
        alt_bn128.G1Point c,
        uint256[n] ls_x,
        uint256[n] ls_y,
        uint256[n] rs_x,
        uint256[n] rs_y,
        uint256 A,
        uint256 B,
        alt_bn128.G1Point[m] hs,
        alt_bn128.G1Point H
    ) public view returns (bool) {
        Board memory b;
        b.c = c;
        for (uint8 i = 0; i < n; i++) {
            b.l = alt_bn128.G1Point(ls_x[i], ls_y[i]);
            b.r = alt_bn128.G1Point(rs_x[i], rs_y[i]);
            b.x = uint256(keccak256(b.l.X, b.l.Y, b.c.X, b.c.Y, b.r.X, b.r.Y)).mod();
            b.xInv = b.x.inv();
            b.c = b.l.mul(b.x.exp(2))
                .add(b.r.mul(b.xInv.exp(2)))
                .add(b.c);
            b.challenges[i] = b.x;
        }

        b.otherExponents[0] = b.challenges[0];
        for (i = 1; i < n; i++) {
            b.otherExponents[0] = b.otherExponents[0].mul(b.challenges[i]);
        }
        b.otherExponents[0] = b.otherExponents[0].inv();
        for (i = 0; i < m/2; ++i) {
            for (uint256 j = 0; (uint256(1) << j) + i < m; ++j) {
                uint256 i1 = i + (uint256(1) << j);
                if (!b.bitSet[i1]) {
                    b.z = b.challenges[n-1-j].mul(b.challenges[n-1-j]);
                    b.otherExponents[i1] = b.otherExponents[i].mul(b.z);
                    b.bitSet[i1] = true;
                }
            }
        }

        b.g = multiExpGs(b.otherExponents);
        b.h = multiExpHsInversed(b.otherExponents, hs);
        b.prod = A.mul(B);
        b.cProof = b.g.mul(A)
            .add(b.h.mul(B))
            .add(H.mul(b.prod));
        return b.cProof.X == b.c.X && b.cProof.Y == b.c.Y;
    }

    function multiExpGs(uint256[m] ss) internal view returns (alt_bn128.G1Point g) {
        g = gs[0].mul(ss[0]);
        for (uint8 i = 1; i < m; i++) {
            g = g.add(gs[i].mul(ss[i]));
        }
    }

    function multiExpHsInversed(uint256[m] ss, alt_bn128.G1Point[m] hs) internal view returns (alt_bn128.G1Point h) {
        h = hs[0].mul(ss[m-1]);
        for (uint8 i = 1; i < m; i++) {
            h = h.add(hs[i].mul(ss[m-1-i]));
        }
    }
    
}


contract RangeProofVerifier {
    using alt_bn128 for uint256;
    using alt_bn128 for alt_bn128.G1Point;

    uint256 public constant m = 4;
    uint256 public constant n = 2;

    alt_bn128.G1Point[m] public gs;
    alt_bn128.G1Point[m] public hs;
    alt_bn128.G1Point public peddersenBaseG;
    alt_bn128.G1Point public peddersenBaseH;

    uint256[m] internal twos = powers(2);

    EfficientInnerProductVerifier public ipVerifier;

    function RangeProofVerifier(
        uint256[4] coords, // [peddersenBaseG_x, peddersenBaseG_y, peddersenBaseH_x, peddersenBaseH_y]
        uint256[2 * m] gs_coords,
        uint256[2 * m] hs_coords,
        EfficientInnerProductVerifier _ipVerifier
    ) public {
        peddersenBaseG = alt_bn128.G1Point(coords[0], coords[1]);
        peddersenBaseH = alt_bn128.G1Point(coords[2], coords[3]);
        for (uint8 i = 0; i < m; i++) {
            gs[i] = alt_bn128.G1Point(gs_coords[i], gs_coords[m + i]);
            hs[i] = alt_bn128.G1Point(hs_coords[i], hs_coords[m + i]);
        }
        ipVerifier = _ipVerifier;
    }

    function verify(
        uint256[10] coords, // [input_x, input_y, A_x, A_y, S_x, S_y, commits[0]_x, commits[0]_y, commits[1]_x, commits[1]_y]
        uint256[5] scalars, // [tauX, mu, t, a, b]
        uint256[2*n] ls_coords, // 2 * n
        uint256[2*n] rs_coords  // 2 * n
    ) external view returns (bool) {
        RangeProof memory rangeProof;
        alt_bn128.G1Point memory input = alt_bn128.G1Point(coords[0], coords[1]);
        rangeProof.A = alt_bn128.G1Point(coords[2], coords[3]);
        rangeProof.S = alt_bn128.G1Point(coords[4], coords[5]);
        rangeProof.commits = [alt_bn128.G1Point(coords[6], coords[7]), alt_bn128.G1Point(coords[8], coords[9])];
        rangeProof.tauX = scalars[0];
        rangeProof.mu = scalars[1];
        rangeProof.t = scalars[2];
        InnerProductProof memory ipProof;
        rangeProof.ipProof = ipProof;
        for (uint8 i = 0; i < n; i++) {
            ipProof.ls[i] = alt_bn128.G1Point(ls_coords[i], ls_coords[n + i]);
            ipProof.rs[i] = alt_bn128.G1Point(rs_coords[i], rs_coords[n + i]);
        }
        ipProof.a = scalars[3];
        ipProof.b = scalars[4];
        return verifyInternal(input, rangeProof);
    }

    struct RangeProof {
        alt_bn128.G1Point A;
        alt_bn128.G1Point S;
        alt_bn128.G1Point[2] commits;
        uint256 tauX;
        uint256 mu;
        uint256 t;
        InnerProductProof ipProof;
    }

    struct InnerProductProof {
        alt_bn128.G1Point[n] ls;
        alt_bn128.G1Point[n] rs;
        uint256 a;
        uint256 b;
    }

    event Proof(uint256 x, uint256 y);

    struct Board {
        uint256 y;
        uint256[m] ys;
        uint256 z;
        uint256 zSquared;
        uint256 zCubed;
        uint256[m] twoTimesZSquared;
        uint256 x;
        alt_bn128.G1Point lhs;
        uint256 k;
        alt_bn128.G1Point rhs;
        uint256 uChallenge;
        alt_bn128.G1Point u;
        alt_bn128.G1Point P;
    }

    function verifyInternal(
        alt_bn128.G1Point input,
        RangeProof proof
    ) internal view returns (bool) {
        Board memory b;
        b.y = uint256(keccak256(input.X, input.Y, proof.A.X, proof.A.Y, proof.S.X, proof.S.Y)).mod();
        b.ys = powers(b.y);
        b.z = uint256(keccak256(b.y)).mod();
        b.zSquared = b.z.mul(b.z);
        b.zCubed = b.zSquared.mul(b.z);
        b.twoTimesZSquared = times(twos, b.zSquared);
        b.x = uint256(keccak256(proof.commits[0].X, proof.commits[0].Y, proof.commits[1].X, proof.commits[1].Y)).mod();
        b.lhs = peddersenBaseG.mul(proof.t).add(peddersenBaseH.mul(proof.tauX));
        b.k = sumScalars(b.ys).mul(b.z.sub(b.zSquared)).sub(b.zCubed.mul(2 ** m).sub(b.zCubed));
        b.rhs = proof.commits[0].mul(b.x).add(proof.commits[1].mul(b.x.mul(b.x)));
        b.rhs = b.rhs.add(input.mul(b.zSquared));
        b.rhs = b.rhs.add(peddersenBaseG.mul(b.k));
        if (!b.rhs.eq(b.lhs)) {
            return false;
        }
        b.uChallenge = uint256(keccak256(proof.tauX, proof.mu, proof.t)).mod();
        b.u = peddersenBaseG.mul(b.uChallenge);
        alt_bn128.G1Point[m] memory hPrimes = haddamard_inv(hs, b.ys);
        uint256[m] memory hExp = addVectors(times(b.ys, b.z), b.twoTimesZSquared);
        b.P = proof.A.add(proof.S.mul(b.x));
        b.P = b.P.add(sumPoints(gs).mul(b.z.neg()));
        b.P = b.P.add(commit(hPrimes, hExp));
        b.P = b.P.add(peddersenBaseH.mul(proof.mu).neg());
        b.P = b.P.add(b.u.mul(proof.t));
        return ipVerifier.verifyWithCustomParams(b.P, toXs(proof.ipProof.ls), toYs(proof.ipProof.ls), toXs(proof.ipProof.rs), toYs(proof.ipProof.rs), proof.ipProof.a, proof.ipProof.b, hPrimes, b.u);
    }

    function addVectors(uint256[m] a, uint256[m] b) internal pure returns (uint256[m] result) {
        for (uint8 i = 0; i < m; i++) {
            result[i] = a[i].add(b[i]);
        }
    }

    function haddamard_inv(alt_bn128.G1Point[m] ps, uint256[m] ss) internal view returns (alt_bn128.G1Point[m] result) {
        for (uint8 i = 0; i < m; i++) {
            result[i] = ps[i].mul(ss[i].inv());
        }
    }

    function sumScalars(uint256[m] ys) internal pure returns (uint256 result) {
        for (uint8 i = 0; i < m; i++) {
            result = result.add(ys[i]);
        }
    }

    function sumPoints(alt_bn128.G1Point[m] ps) internal view returns (alt_bn128.G1Point sum) {
        sum = ps[0];
        for (uint8 i = 1; i < m; i++) {
            sum = sum.add(ps[i]);
        }
    }

    function commit(alt_bn128.G1Point[m] ps, uint256[m] ss) internal view returns (alt_bn128.G1Point commit) {
        commit = ps[0].mul(ss[0]);
        for (uint8 i = 1; i < m; i++) {
            commit = commit.add(ps[i].mul(ss[i]));
        }
    }

    function toXs(alt_bn128.G1Point[n] ps) internal pure returns (uint256[n] xs) {
        for (uint8 i = 0; i < n; i++) {
            xs[i] = ps[i].X;
        }
    }

    function toYs(alt_bn128.G1Point[n] ps) internal pure returns (uint256[n] ys) {
        for (uint8 i = 0; i < n; i++) {
            ys[i] = ps[i].Y;
        }
    }

    function powers(uint256 base) internal pure returns (uint256[m] powers) {
        powers[0] = 1;
        powers[1] = base;
        for (uint8 i = 2; i < m; i++) {
            powers[i] = powers[i-1].mul(base);
        }
    }

    function times(uint256[m] v, uint256 x) internal pure returns (uint256[m] result) {
        for (uint8 i = 0; i < m; i++) {
            result[i] = v[i].mul(x);
        }
    }
}