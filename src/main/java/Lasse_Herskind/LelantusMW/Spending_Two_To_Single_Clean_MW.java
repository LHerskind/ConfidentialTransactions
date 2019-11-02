package Lasse_Herskind.LelantusMW;

import Lasse_Herskind.LelantusConstants;
import Lasse_Herskind.LelantusUtils;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofProverMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofVerifierMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyWitnessMW;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class Spending_Two_To_Single_Clean_MW {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;
    private static int[] l_bin;
    private static BigInteger[][] a;

    private static void init(int size) {
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(size, curve);
    }

    public static void main(String[] args) throws VerificationFailedException {
        /**
         * In this one we try do something else.
         * Instead of extracting some value V, we will extract the a commitment output_coin
         * Which is a normal Pedersen commitment, i.e., gV+hR.
         */

        long start_time = System.currentTimeMillis();

        // First, we need to make an anonymity set, let us use n = 2 and m = 2 for N = 4
        int n = LelantusConstants.n;
        int m = LelantusConstants.m;
        int N = (int) Math.pow(n, m);
        System.out.println("n: " + n + ", m: " + m + ", N: " + N);
        init(N);

        // We Mint the transaction
        BigInteger V1 = BigInteger.valueOf(25);
        BigInteger V2 = BigInteger.valueOf(25);
        BigInteger V = V1.add(V2);

        BigInteger q1 = ProofUtils.randomNumber();
        GroupElement Q1 = params.getBase().g.multiply(q1);
        BigInteger S1 = ProofUtils.hash(Q1.toString());
        BigInteger R1 = ProofUtils.randomNumber();

        BigInteger q2 = ProofUtils.randomNumber();
        GroupElement Q2 = params.getBase().g.multiply(q2);
        BigInteger S2 = ProofUtils.hash(Q2.toString());
        BigInteger R2 = ProofUtils.randomNumber();


        DoubleBlindedPedersenCommitment shielded_coin1 = LelantusUtils.getDBPedersen(params, S1, V1, R1);
        System.out.println("shielded_coin1: \t\t\t\t" + shielded_coin1.getCommitment().stringRepresentation());
        DoubleBlindedPedersenCommitment shielded_coin2 = LelantusUtils.getDBPedersen(params, S2, V2, R2);
        System.out.println("shielded_coin2: \t\t\t\t" + shielded_coin2.getCommitment().stringRepresentation());

        DoubleBlindedPedersenCommitment output_coin = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V1.add(V2), ProofUtils.randomNumber());
        System.out.println("coin_extracted: \t" + output_coin.getCommitment().stringRepresentation());

        System.out.println("--- spending ---");

        System.out.println("Reveal S1: " + S1);
        System.out.println("Reveal S2: " + S2);

        // Hvad kommer der egentligt til at ske her når vi prøver det her? HMMM
        DoubleBlindedPedersenCommitment serialNumber1 = LelantusUtils.getDBPedersen(params, S1, BigInteger.ZERO, BigInteger.ZERO).add(output_coin);
        DoubleBlindedPedersenCommitment serialNumber2 = LelantusUtils.getDBPedersen(params, S2, BigInteger.ZERO, BigInteger.ZERO).add(output_coin);
        System.out.println("Serial Number Point: " + serialNumber1.getCommitment().stringRepresentation());
        System.out.println("Serial Number Point: " + serialNumber2.getCommitment().stringRepresentation());

        // TODO: Implement the 1-out-of-N proofs below!

        GroupElement[] CMList1 = new GroupElement[N];
        GroupElement[] CMList2 = new GroupElement[N];
        for (int i = 0; i < N - 1; i++) {
            CMList1[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
            CMList2[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
        }
        CMList1[N - 1] = shielded_coin1.getCommitment();
        CMList2[N - 1] = shielded_coin2.getCommitment();
        for (int i = 0; i < N; i++) {
            CMList1[i] = CMList1[i].subtract(serialNumber1.getCommitment());
            CMList2[i] = CMList2[i].subtract(serialNumber2.getCommitment());
        }

        OneOutOfManyProofProverMW oneOutOfManyProofProverMW = new OneOutOfManyProofProverMW();
        OneOutOfManyProofVerifierMW oneOutOfManyProofVerifierMW = new OneOutOfManyProofVerifierMW();

        OneOutOfManyWitnessMW oneOutOfManyWitnessMW1 = new OneOutOfManyWitnessMW(N-1, shielded_coin1, output_coin);
        OneOutOfManyProofMW oneOutOfManyProofMW1 = oneOutOfManyProofProverMW.generateProof(params, CMList1, oneOutOfManyWitnessMW1);
        oneOutOfManyProofVerifierMW.verify(params, CMList1, oneOutOfManyProofMW1);

        OneOutOfManyWitnessMW oneOutOfManyWitnessMW2 = new OneOutOfManyWitnessMW(N-1, shielded_coin2, output_coin);
        OneOutOfManyProofMW oneOutOfManyProofMW2 = oneOutOfManyProofProverMW.generateProof(params, CMList2, oneOutOfManyWitnessMW2);
        oneOutOfManyProofVerifierMW.verify(params, CMList2, oneOutOfManyProofMW2);

        OneOutOfManyProofMW[] proofs = {oneOutOfManyProofMW1, oneOutOfManyProofMW2};
        OneOutOfManyWitnessMW[] witnesses = {oneOutOfManyWitnessMW1, oneOutOfManyWitnessMW2};
        BigInteger private_A = LelantusUtils.getAPrivateMultiple(params, proofs, witnesses);
        GroupElement public_A = LelantusUtils.getAPublic(params, oneOutOfManyProofMW1, oneOutOfManyProofMW2);

        if (!public_A.equals(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, private_A).getCommitment())) {
            throw new VerificationFailedException();
        }

        System.out.println("It works");

        System.out.println(System.currentTimeMillis() - start_time);
    }



}
