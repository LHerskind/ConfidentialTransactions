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

    public static void main(String[] args) throws VerificationFailedException {
        BN128Group curve = new BN128Group();

        BigInteger maxValue = BigInteger.valueOf(16);
        int goalLength = maxValue.bitLength();
        int length = 1;
        do {
            length *= 2;
        } while (length < goalLength);
        GeneratorParams parameters = GeneratorParams.generateParams(length, curve);
        BigInteger lambda = ProofUtils.randomNumber();
        BigInteger lambda2 = ProofUtils.randomNumber();

        // Nogle af de vigtige ting
        BigInteger balanceBefore = BigInteger.valueOf(15);
        BigInteger amountToSend = BigInteger.valueOf(-2);
        BigInteger balanceAfter = balanceBefore.add(amountToSend);

        GroupElement commitmentBefore = parameters.getBase().commit(balanceBefore, lambda);
        GroupElement commitmentAmount = parameters.getBase().commit(amountToSend, lambda2);

        GroupElement commitmentAfter = commitmentBefore.add(commitmentAmount);

        KnowledgeProofProver prover = new KnowledgeProofProver();

        KnowledgeProof knowledgeProofBefore = prover.generateProof(parameters, commitmentBefore, new PeddersenCommitment(parameters.getBase(), balanceBefore, lambda));
        KnowledgeProof knowledgeProofAmount = prover.generateProof(parameters, commitmentAmount, new PeddersenCommitment(parameters.getBase(), amountToSend, lambda2));
        KnowledgeProof knowledgeProofAfter = new KnowledgeProofProver().generateProof(parameters, commitmentAfter, new PeddersenCommitment(parameters.getBase(), balanceBefore.add(amountToSend), lambda.add(lambda2)));


        GroupElement v = parameters.getBase().commit(balanceAfter, lambda);
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment(parameters.getBase(), balanceAfter, lambda);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);

        VectorX<GroupElement> commitments = VectorX.of(commitmentBefore, commitmentAmount, commitmentAfter, v);
        VectorX<Proof> proofs = VectorX.of(knowledgeProofBefore, knowledgeProofAmount, knowledgeProofAfter, proof);

        new TransactionProofVerifier().verify(parameters, commitments, proofs);

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

/*
        new KnowledgeProofVerifier().verify(parameters, commitmentBefore, knowledgeProofBefore);
        new KnowledgeProofVerifier().verify(parameters, commitmentAmount, knowledgeProofAmount);
        new KnowledgeProofVerifier().verify(parameters, commitmentAfter, knowledgeProofAfter);
        new RangeProofVerifier().verify(parameters, v, proof);
  */
    }


}
