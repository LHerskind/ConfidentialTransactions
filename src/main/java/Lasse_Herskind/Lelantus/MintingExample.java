package Lasse_Herskind.Lelantus;

import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProof;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofProver;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofVerifier;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
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

    private static DoubleBlindedPedersenCommitment getDBPedersen(BigInteger serial,BigInteger value, BigInteger r2){
        return new DoubleBlindedPedersenCommitment(params.getBase(), serial, value, r2);
    }

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

        // Midway, we generate some stuff, known to the prover
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        BigInteger R = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment coin = getDBPedersen(S, V, R);
        System.out.println("coin: \t\t" + coin.getCommitment().stringRepresentation());

        // To calculate the discrete log relation C/h1^V = g^S*h2^R we first calculate C/H1^V
        DoubleBlindedPedersenCommitment discreteLogRelation = coin.add(getDBPedersen(BigInteger.ZERO, V.negate(), BigInteger.ZERO));
        System.out.println("Discrete Relation, left hand size:\t" + discreteLogRelation.getCommitment().stringRepresentation());
        System.out.println(discreteLogRelation.getSerial() + " : " + discreteLogRelation.getValue() + " : " + discreteLogRelation.getRandom());

        GeneralizedSchnorrProof generalizedSchnorrProof =  generalizedSchnorrProofProver.generateProof(params, discreteLogRelation.getCommitment(), discreteLogRelation);
        generalizedSchnorrProofVerifier.verify(params, discreteLogRelation.getCommitment(), generalizedSchnorrProof);

        System.out.println("The discrete relation holds! Proven with a generalized Schnorr Proof");
        System.out.println("q: " + q + ", V: " +V + ", R: " + R);
    }






}
