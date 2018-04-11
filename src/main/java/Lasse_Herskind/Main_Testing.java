package Lasse_Herskind;

import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProof;
import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProofProver;
import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProofVerifier;
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
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofVerifier;
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

    private static void print2RL(InnerProductProof productProof, InnerProductProof productProof2) {
        System.out.print("[");
        List<BigInteger> ls_coords = listCoords(productProof.getL());
        for (int i = 0; i < ls_coords.size() - 1; i++) {
            System.out.print("\"0x" + ls_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + ls_coords.get(ls_coords.size() - 1).toString(16) + "\", ");
        ls_coords = listCoords(productProof2.getL());
        for (int i = 0; i < ls_coords.size() - 1; i++) {
            System.out.print("\"0x" + ls_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + ls_coords.get(ls_coords.size() - 1).toString(16) + "\"], [");


        List<BigInteger> rs_coords = listCoords(productProof.getR());
        for (int i = 0; i < rs_coords.size() - 1; i++) {
            System.out.print("\"0x" + rs_coords.get(i).toString(16) + "\", ");
        }
        System.out.print("\"0x" + rs_coords.get(rs_coords.size() - 1).toString(16) + "\", ");
        rs_coords = listCoords(productProof2.getR());
        for (int i = 0; i < rs_coords.size() - 1; i++) {
            System.out.print("\"0x" + rs_coords.get(i).toString(16) + "\", ");
        }
        System.out.println("\"0x" + rs_coords.get(rs_coords.size() - 1).toString(16) + "\"]");
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

        BigInteger maxValue = BigInteger.valueOf(6);
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
            mint_then_transfer_and_receive(parameters);
//            test_transfer_and_recieve(parameters);
        }
    }

    private static void mint_then_transfer_and_receive(GeneratorParams params) throws VerificationFailedException {
        RangeProofVerifier rangeProofVerifier = new RangeProofVerifier();
        RangeProofProver rangeProofProver = new RangeProofProver();
        KnowledgeProofVerifier knowledgeProofVerifier = new KnowledgeProofVerifier();
        KnowledgeProofProver knowledgeProofProver = new KnowledgeProofProver();

        // 2 users, both have zero coins and 0 as lambda
        BigInteger lambdaUser1 = BigInteger.ZERO;
        BigInteger lambdaUser2 = BigInteger.ZERO;
        BigInteger balanceUser1 = BigInteger.ZERO;
        BigInteger balanceUser2 = BigInteger.ZERO;

        // We mint 5 coins to the user1/0x28
        BigInteger mintAmount = BigInteger.valueOf(5);
        BigInteger lambdaMintAmount = BigInteger.valueOf(98614250);
        PeddersenCommitment<BouncyCastleECPoint> witnessMint = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), mintAmount, lambdaMintAmount);
        System.out.println("Mint-commitment:");
        System.out.println(pointToBigInts(witnessMint.getCommitment()));

        // We accept the 5 coins
        lambdaUser1 = lambdaUser1.add(lambdaMintAmount);
        balanceUser1 = balanceUser1.add(mintAmount);

        PeddersenCommitment<BouncyCastleECPoint> witnessUser1AfterMint = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), balanceUser1, lambdaUser1);
        KnowledgeProof knowledgeProofReceive = knowledgeProofProver.generateProof(params, witnessUser1AfterMint.getCommitment(), witnessUser1AfterMint);
        knowledgeProofVerifier.verify(params, witnessUser1AfterMint.getCommitment(), knowledgeProofReceive);
        printAbleFormatKnowledgeProof(witnessUser1AfterMint.getCommitment(), knowledgeProofReceive);

        // We send 3 coins from user1 to user2
        BigInteger transferAmount = BigInteger.valueOf(3);
        BigInteger lambdaTransfer = BigInteger.valueOf(48179);

        PeddersenCommitment<BouncyCastleECPoint> witnessAmount = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), transferAmount, lambdaTransfer);
        RangeProof transferAmountProof = rangeProofProver.generateProof(params, witnessAmount.getCommitment(), witnessAmount);
        rangeProofVerifier.verify(params, witnessAmount.getCommitment(), transferAmountProof);

        balanceUser1 = balanceUser1.subtract(transferAmount);
        lambdaUser1 = lambdaUser1.subtract(lambdaTransfer);

        PeddersenCommitment<BouncyCastleECPoint> witnessBalanceUser1After = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), balanceUser1, lambdaUser1);
        RangeProof balanceUser1AfterProof = rangeProofProver.generateProof(params, witnessBalanceUser1After.getCommitment(), witnessBalanceUser1After);
        rangeProofVerifier.verify(params, witnessBalanceUser1After.getCommitment(), balanceUser1AfterProof);

        print2RangeProof_Ethereum(witnessAmount.getCommitment(), witnessBalanceUser1After.getCommitment(), transferAmountProof, balanceUser1AfterProof);

        // We receive the 3 coins as user2
        balanceUser2 = balanceUser2.add(transferAmount);
        lambdaUser2 = lambdaUser2.add(lambdaTransfer);

        PeddersenCommitment<BouncyCastleECPoint> witnessBalanceUser2After = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), balanceUser2, lambdaUser2);
        KnowledgeProof knowledgeProofBalanceUser2 = knowledgeProofProver.generateProof(params, witnessBalanceUser2After.getCommitment(), witnessBalanceUser2After);
        knowledgeProofVerifier.verify(params, witnessBalanceUser2After.getCommitment(), knowledgeProofBalanceUser2);
        printAbleFormatKnowledgeProof(witnessBalanceUser2After.getCommitment(), knowledgeProofBalanceUser2);
    }

    private static void test_transfer_and_recieve(GeneratorParams params) throws VerificationFailedException {
        RangeProofVerifier rangeProofVerifier = new RangeProofVerifier();
        RangeProofProver rangeProofProver = new RangeProofProver();
        KnowledgeProofVerifier knowledgeProofVerifier = new KnowledgeProofVerifier();
        KnowledgeProofProver knowledgeProofProver = new KnowledgeProofProver();

        BigInteger lambdaTransaction = BigInteger.valueOf(6541); //ProofUtils.randomNumber();
        BigInteger amountToSend = BigInteger.valueOf(5);

        BigInteger balanceUser1 = BigInteger.valueOf(5);
        BigInteger lambdaBalanceUser1 = BigInteger.valueOf(2643); //ProofUtils.randomNumber();
        BigInteger balanceUser1After = balanceUser1.subtract(amountToSend);

        BigInteger balanceUser2 = BigInteger.valueOf(0);
        BigInteger lambdaBalanceUser2 = BigInteger.ZERO; //ProofUtils.randomNumber(); //
        BigInteger balanceUser2After = balanceUser2.add(amountToSend);

        // Sender proofs
        PeddersenCommitment<BouncyCastleECPoint> witnessAmount = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), amountToSend, lambdaTransaction);
        PeddersenCommitment<BouncyCastleECPoint> witnessBalance1After = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), balanceUser1After, lambdaBalanceUser1.subtract(lambdaTransaction));
        PeddersenCommitment<BouncyCastleECPoint> witnessBalance2After = new PeddersenCommitment<BouncyCastleECPoint>(params.getBase(), balanceUser2After, lambdaBalanceUser2.add(lambdaTransaction));

        RangeProof amountProof = rangeProofProver.generateProof(params, witnessAmount.getCommitment(), witnessAmount);
        RangeProof balance1AfterProof = rangeProofProver.generateProof(params, witnessBalance1After.getCommitment(), witnessBalance1After);
        rangeProofVerifier.verify(params, witnessAmount.getCommitment(), amountProof);
        rangeProofVerifier.verify(params, witnessBalance1After.getCommitment(), balance1AfterProof);

        print2RangeProof_Ethereum(witnessAmount.getCommitment(), witnessBalance1After.getCommitment(), amountProof, balance1AfterProof);

        // Receiver
        KnowledgeProof knowledgeProofReceive = knowledgeProofProver.generateProof(params, witnessBalance2After.getCommitment(), witnessBalance2After);
        knowledgeProofVerifier.verify(params, witnessBalance2After.getCommitment(), knowledgeProofReceive);
        printAbleFormatKnowledgeProof(witnessBalance2After.getCommitment(), knowledgeProofReceive);
    }

    private static void printRangeProof_Ethereum(GroupElement commitment, RangeProof proof) {
        System.out.println("RangeProofVerifier inputs, from commitment and proof");
        System.out.print("[" + pointToBigInts(commitment) + ", " + pointToBigInts(proof.getaI()) + ", " + pointToBigInts(proof.getS()) + ", " + pointToBigInts(proof.gettCommits().get(0)) + ", " + pointToBigInts(proof.gettCommits().get(1)) + "], ");
        System.out.print("[" + bigIntToHexString(proof.getTauX()) + ", " + bigIntToHexString(proof.getMu()) + ", " + bigIntToHexString(proof.getT()) + ", " + bigIntToHexString(proof.getProductProof().getA()) + ", " + bigIntToHexString(proof.getProductProof().getB()) + "], ");
        printRL(proof.getProductProof());
    }

    private static void print2RangeProof_Ethereum(GroupElement commitment1, GroupElement commitment2, RangeProof proof, RangeProof proof2) {
        System.out.println("DoubleRangeProofVerifier inputs, from commitments and proofs");
        System.out.print("[" + pointToBigInts(commitment1) + ", " + pointToBigInts(proof.getaI()) + ", " + pointToBigInts(proof.getS()) + ", " + pointToBigInts(proof.gettCommits().get(0)) + ", " + pointToBigInts(proof.gettCommits().get(1)) + ", ");
        System.out.print("" + pointToBigInts(commitment2) + ", " + pointToBigInts(proof2.getaI()) + ", " + pointToBigInts(proof2.getS()) + ", " + pointToBigInts(proof2.gettCommits().get(0)) + ", " + pointToBigInts(proof2.gettCommits().get(1)) + "], ");
        System.out.print("[" + bigIntToHexString(proof.getTauX()) + ", " + bigIntToHexString(proof.getMu()) + ", " + bigIntToHexString(proof.getT()) + ", " + bigIntToHexString(proof.getProductProof().getA()) + ", " + bigIntToHexString(proof.getProductProof().getB()) + ", ");
        System.out.print("" + bigIntToHexString(proof2.getTauX()) + ", " + bigIntToHexString(proof2.getMu()) + ", " + bigIntToHexString(proof2.getT()) + ", " + bigIntToHexString(proof2.getProductProof().getA()) + ", " + bigIntToHexString(proof2.getProductProof().getB()) + "], ");
        print2RL(proof.getProductProof(), proof2.getProductProof());
    }


    public static void printAbleFormatKnowledgeProof(GroupElement commitment, KnowledgeProof proof) {
        System.out.println("KnowledgeProofVerifier inputs, from proof");
        String output = "[";
        //output += pointToBigInts(commitment) + ",";
        output += pointToBigInts(proof.getA()) + ",";
        output += pointToBigInts(proof.getT()) + ",";
        output += pointToBigInts(proof.getS()) + "]";
        System.out.println(output);
    }

}
