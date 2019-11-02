package Lasse_Herskind.Lelantus;

import Lasse_Herskind.LelantusUtils;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProof;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProofProver;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProofVerifier;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyWitness;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class Spending_Two_Clean {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;

    private static void init(int size) {
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(size, curve);
    }

    public static void main(String[] args) throws VerificationFailedException {
        long start_time = System.currentTimeMillis();

        // First, we need to make an anonymity set, let us use n = 2 and m = 2 for N = 4
        int n = 2;
        int m = 2;
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

        DoubleBlindedPedersenCommitment coin1 = LelantusUtils.getDBPedersen(params, S1, V1, R1);
        DoubleBlindedPedersenCommitment coin2 = LelantusUtils.getDBPedersen(params, S2, V2, R2);
        System.out.println("coin1: \t\t" + coin1.getCommitment().stringRepresentation());
        System.out.println("coin2: \t\t" + coin2.getCommitment().stringRepresentation());

        System.out.println("--- spending ---");

        System.out.println("Reveal S1: " + S1);
        System.out.println("Reveal S2: " + S2);

        DoubleBlindedPedersenCommitment serialNumber1 = LelantusUtils.getDBPedersen(params, S1, BigInteger.ZERO, BigInteger.ZERO);
        DoubleBlindedPedersenCommitment serialNumber2 = LelantusUtils.getDBPedersen(params, S2, BigInteger.ZERO, BigInteger.ZERO);
        System.out.println("Serial Number Point1: " + serialNumber1.getCommitment().stringRepresentation());
        System.out.println("Serial Number Point2: " + serialNumber2.getCommitment().stringRepresentation());

        // TODO: Implement the 1-out-of-N proofs below!
        GroupElement[] CMList1 = new GroupElement[N];
        GroupElement[] CMList2 = new GroupElement[N];
        for (int i = 0; i < N - 1; i++) {
            CMList1[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
            CMList2[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
        }
        CMList1[N - 1] = coin1.getCommitment();
        CMList2[N - 1] = coin2.getCommitment();
        for (int i = 0; i < N; i++) {
            CMList1[i] = CMList1[i].subtract(serialNumber1.getCommitment());
            CMList2[i] = CMList2[i].subtract(serialNumber2.getCommitment());
        }
        OneOutOfManyProofProver oneOutOfManyProofProver = new OneOutOfManyProofProver();
        OneOutOfManyProofVerifier oneOutOfManyProofVerifier = new OneOutOfManyProofVerifier();

        // Proof 1
        OneOutOfManyWitness oneOutOfManyWitness1 = new OneOutOfManyWitness(N - 1, coin1);
        OneOutOfManyProof oneOutOfManyProof1 = oneOutOfManyProofProver.generateProof(params, CMList1, oneOutOfManyWitness1);
        oneOutOfManyProofVerifier.verify(params, CMList1, oneOutOfManyProof1);

        OneOutOfManyWitness oneOutOfManyWitness2 = new OneOutOfManyWitness(N - 1, coin2);
        OneOutOfManyProof oneOutOfManyProof2 = oneOutOfManyProofProver.generateProof(params, CMList2, oneOutOfManyWitness2);
        oneOutOfManyProofVerifier.verify(params, CMList2, oneOutOfManyProof2);

        // The proof of no value creation
        /**
         * TODO: Need to make some better for finding the challenge x, the important part is that x is the same across the entire transaction!
         * For now we are just using q to find the challenge, this is not good enough!
         */
        OneOutOfManyProof[] proofs = {oneOutOfManyProof1, oneOutOfManyProof2};
        OneOutOfManyWitness[] witnesses = {oneOutOfManyWitness1, oneOutOfManyWitness2};
        BigInteger private_A = LelantusUtils.getAPrivateMultiple(params, proofs, witnesses);
        GroupElement public_A = LelantusUtils.getAPublic(params, V, oneOutOfManyProof1, oneOutOfManyProof2);

        if (!public_A.equals(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, private_A).getCommitment())) {
            throw new VerificationFailedException();
        }

        System.out.println("It works");

        System.out.println(System.currentTimeMillis() - start_time);
    }


}
