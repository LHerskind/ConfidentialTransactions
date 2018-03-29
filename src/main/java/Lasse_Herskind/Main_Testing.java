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
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofProver;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.List;

import static edu.stanford.cs.crypto.efficientct.ethereum.Utils.listCoords;

public class Main_Testing {

    static boolean setupPhase = false;

    private static String bigIntToHexString(BigInteger input) {
        return "\"0x" + input.toString(16) + "\"";
    }

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

    public static void printableFormatRangeProof(GroupElement commitment, RangeProof proof) {
        String output = "";
        output += pointToBigInts(commitment);
    }

    public static void printableSetupFormatEfficientInnerProductVerifier_Human(GeneratorParams params) {
        System.out.println("Human input, efficientInnerProductVerifier:");
        System.out.println(params.getVectorBase().getH());
        System.out.println(params.getVectorBase().getGs());
        System.out.println(params.getVectorBase().getHs());
    }

    private static void printRL(InnerProductProof productProof) {
        System.out.print("[");
        List<BigInteger> ls_coords = listCoords(productProof.getL());
        for (int i = 0; i < ls_coords.size() - 1; i++) {
            System.out.print("\"0x" + ls_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + ls_coords.get(ls_coords.size() - 1).toString(16) + "\"], [");

        List<BigInteger> rs_coords = listCoords(productProof.getR());
        for (int i = 0; i < rs_coords.size() - 1; i++) {
            System.out.print("\"0x" + rs_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + rs_coords.get(rs_coords.size() - 1).toString(16) + "\"]");
    }

    private static void printGsHsVectors(GeneratorParams params) {
        System.out.print("[");
        List<BigInteger> gs_coords = listCoords(params.getVectorBase().getGs().getVector());
        for (int i = 0; i < gs_coords.size() - 1; i++) {
            System.out.print("\"0x" + gs_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + gs_coords.get(gs_coords.size() - 1).toString(16) + "\"], [");

        List<BigInteger> hs_coords = listCoords(params.getVectorBase().getHs().getVector());
        for (int i = 0; i < hs_coords.size() - 1; i++) {
            System.out.print("\"0x" + hs_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + hs_coords.get(hs_coords.size() - 1).toString(16) + "\"]");
    }

    private static void printableSetupFormatEfficientInnerProductVerifier_Ethereum(GeneratorParams params) {
        System.out.println("Ethereum input, efficientInnerProductVerifier:");
        System.out.print(pointToBigInts(params.getVectorBase().getH()) + ", ");
        printGsHsVectors(params);
        System.out.println();
    }

    private static void printableSetupFormatRangeProofVerifier_Ethereum(GeneratorParams parameters) {
        System.out.println("Ethereum input, rangeProofVerifier:");
        System.out.print("[" + pointToBigInts(parameters.getBase().g) + ", " + pointToBigInts(parameters.getBase().h) + "], ");
        printGsHsVectors(parameters);
        System.out.print(", ipVerifier");
        System.out.println();
    }

    private static void printableSetupFormatKnowledgeProof_Ethereum(GeneratorParams parameters) {
        System.out.println("Ethereum input, knowledgeProofVerifier:");
        System.out.print("[" + pointToBigInts(parameters.getBase().g) + ", " + pointToBigInts(parameters.getBase().h) + "]");
        System.out.println();
    }


    public static void main(String[] args) throws VerificationFailedException {
        BN128Group curve = new BN128Group();

        BigInteger maxValue = BigInteger.valueOf(4);
        int goalLength = maxValue.bitLength();
        int length = 1;
        do {
            length *= 2;
        } while (length < goalLength);
        System.out.println(length);
        GeneratorParams parameters = GeneratorParams.generateParams(length, curve);

        if (setupPhase) {
            System.out.println("Setup phase");
            System.out.println("Bitlength: " + length);
            printableSetupFormatKnowledgeProof_Ethereum(parameters);
            printableSetupFormatEfficientInnerProductVerifier_Ethereum(parameters);
            printableSetupFormatRangeProofVerifier_Ethereum(parameters);
        } else {
            BigInteger lambda = ProofUtils.randomNumber();
            BigInteger lambda2 = ProofUtils.randomNumber();

            BigInteger balanceBefore = BigInteger.valueOf(100);
            BigInteger amountToSend = BigInteger.valueOf(4);
            BigInteger balanceAfter = balanceBefore.subtract(amountToSend);

            GroupElement commitmentBefore = parameters.getBase().commit(balanceBefore, lambda);
            GroupElement commitmentAmount = parameters.getBase().commit(amountToSend, lambda2);
            GroupElement commitmentAfter = commitmentBefore.subtract(commitmentAmount);

            KnowledgeProofProver prover = new KnowledgeProofProver();

            KnowledgeProof knowledgeProofBefore = prover.generateProof(parameters, commitmentBefore, new PeddersenCommitment(parameters.getBase(), balanceBefore, lambda));
            KnowledgeProof knowledgeProofAmount = prover.generateProof(parameters, commitmentAmount, new PeddersenCommitment(parameters.getBase(), amountToSend, lambda2));
            KnowledgeProof knowledgeProofAfter = prover.generateProof(parameters, commitmentAfter, new PeddersenCommitment(parameters.getBase(), balanceBefore.subtract(amountToSend), lambda.subtract(lambda2)));

/*            System.out.println("The before proof");
            System.out.println(pointToBigInts(commitmentBefore));
            System.out.println(knowledgeProofBefore.getA());
            System.out.println(knowledgeProofBefore.getT());
            System.out.println(knowledgeProofBefore.getS());
            System.out.print("To Geth: ");
            printAbleFormatKnowledgeProof(commitmentBefore, knowledgeProofBefore);
*/
            GroupElement v = parameters.getBase().commit(balanceAfter, lambda);
            PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment(parameters.getBase(), balanceAfter, lambda);
            RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);

            VectorX<GroupElement> commitments = VectorX.of(commitmentBefore, commitmentAmount, commitmentAfter, v);
            VectorX<Proof> proofs = VectorX.of(knowledgeProofBefore, knowledgeProofAmount, knowledgeProofAfter, proof);

            new TransactionProofVerifier().verify(parameters, commitments, proofs);
            /*
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
*/
            printRangeProof_Ethereum(v, proof);
        }
    }

    private static void printRangeProof_Ethereum(GroupElement commitment, RangeProof proof) {
        System.out.println("RangeProofVerifier inputs, from commitment and proof");
        System.out.print("[" + pointToBigInts(commitment) + ", " + pointToBigInts(proof.getaI()) + ", " + pointToBigInts(proof.getS()) + ", " + pointToBigInts(proof.gettCommits().get(0)) + ", " + pointToBigInts(proof.gettCommits().get(1)) + "], ");
        System.out.print("[" + bigIntToHexString(proof.getTauX()) + ", " + bigIntToHexString(proof.getMu()) + ", " + bigIntToHexString(proof.getT()) + ", " + bigIntToHexString(proof.getProductProof().getA()) + ", " + bigIntToHexString(proof.getProductProof().getB()) + "], ");
        printRL(proof.getProductProof());

    }

}
