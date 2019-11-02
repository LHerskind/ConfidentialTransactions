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

public class Spending_One_Clean {

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
        BigInteger V = BigInteger.valueOf(25);
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        BigInteger R = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment coin = LelantusUtils.getDBPedersen(params, S, V, R);
        System.out.println("coin: \t\t" + coin.getCommitment().stringRepresentation());

        System.out.println("--- spending ---");

        System.out.println("Reveal S: " + S);

        DoubleBlindedPedersenCommitment serialNumber = LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, BigInteger.ZERO);
        System.out.println("Serial Number Point: " + serialNumber.getCommitment().stringRepresentation());

        // TODO: Implement the 1-out-of-N proofs below!
        GroupElement[] CMList = new GroupElement[N];
        CMList[0] = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.valueOf(1), ProofUtils.randomNumber()).getCommitment();
        for (int i = 1; i < N - 1; i++) {
            CMList[i] = LelantusUtils.getDBPedersen(params, ProofUtils.randomNumber(), BigInteger.valueOf(i + 1), ProofUtils.randomNumber()).getCommitment();
        }
        CMList[N - 1] = coin.getCommitment();
        for (int i = 0; i < N; i++) {
            CMList[i] = CMList[i].subtract(serialNumber.getCommitment());
        }

        OneOutOfManyProofProver oneOutOfManyProofProver = new OneOutOfManyProofProver();
        OneOutOfManyWitness oneOutOfManyWitness = new OneOutOfManyWitness(N - 1, coin);
        OneOutOfManyProof oneOutOfManyProof = oneOutOfManyProofProver.generateProof(params, CMList, oneOutOfManyWitness);

        OneOutOfManyProofVerifier oneOutOfManyProofVerifier = new OneOutOfManyProofVerifier();
        oneOutOfManyProofVerifier.verify(params, CMList, oneOutOfManyProof);

        // The proof of no value creation
        BigInteger private_A = LelantusUtils.getAPrivate(params, oneOutOfManyProof, oneOutOfManyWitness);
        GroupElement public_A = LelantusUtils.getAPublic(params, V, oneOutOfManyProof);

        if (!public_A.equals(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, private_A).getCommitment())) {
            throw new VerificationFailedException();
        }

        System.out.println("It works");

        System.out.println(System.currentTimeMillis() - start_time);
    }


}
