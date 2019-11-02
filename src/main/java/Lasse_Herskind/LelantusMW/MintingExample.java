package Lasse_Herskind.LelantusMW;

import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProof;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofProver;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofVerifier;
import Lasse_Herskind.LelantusUtils;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class MintingExample {


    private static BN128Group curve;
    private static DoubleGeneratorParams params;
    private static GeneralizedSchnorrProofProver generalizedSchnorrProofProver;
    private static GeneralizedSchnorrProofVerifier generalizedSchnorrProofVerifier;


    private static void init(){
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(1, curve);
        generalizedSchnorrProofProver = new GeneralizedSchnorrProofProver();
        generalizedSchnorrProofVerifier = new GeneralizedSchnorrProofVerifier();
    }

    public static void main(String[] args) throws VerificationFailedException {
        init();

        // Inputs
        BigInteger V = BigInteger.valueOf(25);
        BigInteger R = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment input_coin = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V, R);

        // Midway, we generate some stuff, known to the prover
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        // We need to make an offset with an additional R hence it will otherwise be possible to link transactions coming in and out of the pool.
        BigInteger R_offset = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment shielded_coin = LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, R_offset).add(input_coin);
        System.out.println("shielded coin: \t\t" + shielded_coin.getCommitment().stringRepresentation());
        System.out.println(shielded_coin.getSerial() + " : " + shielded_coin.getValue() + " : " + shielded_coin.getRandom());

        DoubleBlindedPedersenCommitment discreteLogRelation = shielded_coin.sub(input_coin);
        System.out.println("Discrete Relation, left hand size:\t" + discreteLogRelation.getCommitment().stringRepresentation());
        System.out.println(discreteLogRelation.getSerial() + " : " + discreteLogRelation.getValue() + " : " + discreteLogRelation.getRandom());

        GeneralizedSchnorrProof generalizedSchnorrProof =  generalizedSchnorrProofProver.generateProof(params, discreteLogRelation.getCommitment(), discreteLogRelation);
        generalizedSchnorrProofVerifier.verify(params, discreteLogRelation.getCommitment(), generalizedSchnorrProof);
        System.out.println("The discrete relation holds! Proven with a generalized Schnorr Proof");
    }

}
