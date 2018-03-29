pragma solidity ^0.4.19;
pragma experimental ABIEncoderV2;

import "./alt_bn128.sol";

contract KnowledgeProofVerifier {
    using alt_bn128 for uint256;
    using alt_bn128 for alt_bn128.G1Point;

    alt_bn128.G1Point public peddersenBaseG;
    alt_bn128.G1Point public peddersenBaseH;

    function KnowledgeProofVerifier(
        uint256[4] coords, // [peddersenBaseG_x, peddersenBaseG_y, peddersenBaseH_x, peddersenBaseH_y]
    ) public {
        peddersenBaseG = alt_bn128.G1Point(coords[0], coords[1]);
        peddersenBaseH = alt_bn128.G1Point(coords[2], coords[3]);
    }

    function verify(
        uint256[8] coords // [commitment_x, commitment_y, A_x, A_y, S_x, S_y, T_x,T_y]
    ) external view returns (bool) {
        KnowledgeProof memory knowledgeProof;
        alt_bn128.G1Point memory commitment = alt_bn128.G1Point(coords[0], coords[1]);
        knowledgeProof.A = alt_bn128.G1Point(coords[2], coords[3]);
        knowledgeProof.T = alt_bn128.G1Point(coords[4], coords[5]);
        knowledgeProof.S = alt_bn128.G1Point(coords[6], coords[7]);
        return verifyInternal(commitment, knowledgeProof);
    }

    function verifyInternal(alt_bn128.G1Point input, KnowledgeProof proof) internal view returns (bool) {
        require(input.eq(proof.A));
        uint256 challenge = uint256(keccak256(input.X, input.Y, proof.T.X, proof.T.Y)).mod();
        alt_bn128.G1Point memory verificationPoint = proof.A.mul(challenge).add(proof.T);
        return verificationPoint.eq(proof.S);
    }

    struct KnowledgeProof{
        alt_bn128.G1Point A;
        alt_bn128.G1Point T;
        alt_bn128.G1Point S;
    }

}
