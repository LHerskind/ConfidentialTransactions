package Lasse_Herskind;

import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProof;
import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProofProver;
import Lasse_Herskind.TransactionBalancesKnowledgeProof.TransactionProofVerifier;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofProver;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class Main_Testing {

    public static String pointToBigInts(GroupElement commitment) {
        String input = commitment.stringRepresentation();
        input = input.substring(1, input.length() - 1);
        String[] strings = input.split(",");
        String output = "\"0x" + strings[0] + "\",\"0x" + strings[1] + "\"";
        return output;
    }

    public static void printAbleFormatKnowledgeProof(GroupElement commitment, KnowledgeProof proof) {
        String output = "[";
        output += pointToBigInts(commitment) + ",";
        output += pointToBigInts(proof.getA()) + ",";
        output += pointToBigInts(proof.getT()) + ",";
        output += pointToBigInts(proof.getS()) + "]";
        System.out.println(output);
    }

    public static void printableFormatRangeProof(GroupElement commitment, RangeProof proof){
        String output = "";
        output += pointToBigInts(commitment);
    }

    public static void main(String[] args) throws VerificationFailedException {
        BN128Group curve = new BN128Group();

        BigInteger maxValue = BigInteger.valueOf(15);
        int goalLength = maxValue.bitLength();
        int length = 1;
        do {
            length *= 2;
        } while (length < goalLength);
        System.out.println(length);
        GeneratorParams parameters = GeneratorParams.generateParams(length, curve);
        System.out.println("PedersenBaseG: " + parameters.getBase().g);
        System.out.println("PedersenBaseh: " + parameters.getBase().h);

        BigInteger lambda = ProofUtils.randomNumber();
        BigInteger lambda2 = ProofUtils.randomNumber();

        // Nogle af de vigtige ting
        BigInteger balanceBefore = BigInteger.valueOf(11);
        BigInteger amountToSend = BigInteger.valueOf(2);
        BigInteger balanceAfter = balanceBefore.add(amountToSend);

        GroupElement commitmentBefore = parameters.getBase().commit(balanceBefore, lambda);
        GroupElement commitmentAmount = parameters.getBase().commit(amountToSend, lambda2);
        GroupElement commitmentAfter = commitmentBefore.subtract(commitmentAmount);

        KnowledgeProofProver prover = new KnowledgeProofProver();

        KnowledgeProof knowledgeProofBefore = prover.generateProof(parameters, commitmentBefore, new PeddersenCommitment(parameters.getBase(), balanceBefore, lambda));
        KnowledgeProof knowledgeProofAmount = prover.generateProof(parameters, commitmentAmount, new PeddersenCommitment(parameters.getBase(), amountToSend, lambda2));
        KnowledgeProof knowledgeProofAfter = prover.generateProof(parameters, commitmentAfter, new PeddersenCommitment(parameters.getBase(), balanceBefore.subtract(amountToSend), lambda.subtract(lambda2)));

        System.out.println("The before proof");
        System.out.println(commitmentBefore);
        System.out.println(knowledgeProofBefore.getA());
        System.out.println(knowledgeProofBefore.getT());
        System.out.println(knowledgeProofBefore.getS());
        System.out.print("To Geth: ");
        printAbleFormatKnowledgeProof(commitmentBefore, knowledgeProofBefore);

        GroupElement v = parameters.getBase().commit(balanceAfter, lambda);
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment(parameters.getBase(), balanceAfter, lambda);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);

        VectorX<GroupElement> commitments = VectorX.of(commitmentBefore, commitmentAmount, commitmentAfter, v);
        VectorX<Proof> proofs = VectorX.of(knowledgeProofBefore, knowledgeProofAmount, knowledgeProofAfter, proof);

        new TransactionProofVerifier().verify(parameters, commitments, proofs);

        // For the verification, innerproductproof
        System.out.println("Inner product proof");
        System.out.println(parameters.getVectorBase().getH());
        System.out.println(parameters.getVectorBase().getGs());
        System.out.println(parameters.getVectorBase().getHs());

        // For the verification
        System.out.println("The range proof inputs:");
        System.out.println(v);
        System.out.println(proof.getaI());
        System.out.println(proof.getS());
        System.out.println(proof.gettCommits());
        System.out.println(proof.getTauX());
        System.out.println(proof.getMu());
        System.out.println(proof.getT());
        System.out.println(proof.getProductProof().getA());
        System.out.println(proof.getProductProof().getB());
        System.out.println(proof.getProductProof().getL());
        System.out.println(proof.getProductProof().getR());
    }


}
