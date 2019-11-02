package Lasse_Herskind.LelantusMW;

import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProof;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofProver;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofVerifier;
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

import javax.swing.text.AbstractDocument;
import java.math.BigInteger;

public class Spending_Mint_One_of_each_Clean_V2_MW {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;

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
        BigInteger V = BigInteger.valueOf(25);
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        BigInteger R = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment shielded_coin = LelantusUtils.getDBPedersen(params, S, V, R);
        System.out.println("shielded_coin: \t\t\t\t" + shielded_coin.getCommitment().stringRepresentation());

        DoubleBlindedPedersenCommitment output_coin = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V, ProofUtils.randomNumber());
        System.out.println("coin_extracted: \t" + output_coin.getCommitment().stringRepresentation());

        System.out.println("--- spending ---");

        System.out.println("Reveal S: " + S);

        DoubleBlindedPedersenCommitment serialNumber = LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, BigInteger.ZERO).add(output_coin);
        System.out.println("Serial Number Point: " + serialNumber.getCommitment().stringRepresentation());

        // TODO: Implement the 1-out-of-N proofs below!

        GroupElement[] CMList = new GroupElement[N];
        for (int i = 0; i < N - 1; i++) {
            CMList[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
        }
        CMList[N - 1] = shielded_coin.getCommitment();
        for (int i = 0; i < N; i++) {
            CMList[i] = CMList[i].subtract(serialNumber.getCommitment());
        }

        OneOutOfManyProofProverMW oneOutOfManyProofProverMW = new OneOutOfManyProofProverMW();
        OneOutOfManyProofVerifierMW oneOutOfManyProofVerifierMW = new OneOutOfManyProofVerifierMW();

        OneOutOfManyWitnessMW oneOutOfManyWitnessMW = new OneOutOfManyWitnessMW(N - 1, shielded_coin, output_coin);
        OneOutOfManyProofMW oneOutOfManyProofMW = oneOutOfManyProofProverMW.generateProof(params, CMList, oneOutOfManyWitnessMW);
        oneOutOfManyProofVerifierMW.verify(params, CMList, oneOutOfManyProofMW);

        BigInteger private_A = LelantusUtils.getAPrivate(params, oneOutOfManyProofMW, oneOutOfManyWitnessMW);
        GroupElement public_A = LelantusUtils.getAPublic(params, oneOutOfManyProofMW);

        if (!public_A.equals(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, private_A).getCommitment())) {
            throw new VerificationFailedException();
        }

        /* TODO: What is the transaction we are trying to make
         * We have a shielded output with value of 25, and a normal output of value 10.
         * We want to end up with a shielded of 30, and a normal of 5.
         * Shielded_in -> CoinOutput
         * CoinOutput + Normal_in -> To_shield + Normal_out
         * To_shield -> Shielded_out
         */

        // The above is pretty much just what do for the one-out-of-many proofs. Now let us make the minting of a new coin
        // Remember output_coin, the coin retrieved from the spending!
        DoubleBlindedPedersenCommitment normalSource = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.valueOf(10), ProofUtils.randomNumber());

        // We should not use the serial number here, but instead the output, RIGHT!?
        DoubleBlindedPedersenCommitment publishedSource = output_coin.add(LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, private_A));
        if (!(serialNumber.getCommitment().add(public_A)).equals(publishedSource.getCommitment())) {
            throw new VerificationFailedException();
        }

        DoubleBlindedPedersenCommitment normalDestination = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.valueOf(5), ProofUtils.randomNumber());
        BigInteger V_mint = (normalSource.getValue().add(shielded_coin.getValue()).subtract(normalDestination.getValue())); // This is pretty much an intermediate value
        BigInteger R_mint = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment to_shield = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V_mint, R_mint);

        // Now, for the annoying part, create a transaction
        BigInteger q_mint = ProofUtils.randomNumber();
        GroupElement Q_mint = params.getBase().g.multiply(q_mint);
        BigInteger S_mint = ProofUtils.hash(Q_mint.toString());
        BigInteger R_offset_mint = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment shieldedCoinNew = LelantusUtils.getDBPedersen(params, S_mint, BigInteger.ZERO, R_offset_mint).add(to_shield);

        // Now, we calculate the excess and see what happens
        DoubleBlindedPedersenCommitment excess_inputs = normalSource.add(publishedSource).add(to_shield).add(output_coin);
        DoubleBlindedPedersenCommitment excess_outputs = normalDestination.add(output_coin).add(to_shield).add(shieldedCoinNew);
        // See that a lot of the stuff will be removed in the excess
        DoubleBlindedPedersenCommitment excess = excess_outputs.sub(excess_inputs);
        System.out.println("Excess: " + excess);

        // Now we just need the little offset, to make it hard to reconstruct the original.
        BigInteger k_offset = ProofUtils.randomNumber();
        excess = excess.sub(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, k_offset));
        // Then we simply have (excess, excess_offset, generalised_schnorr_proof) as the kernel.

        GeneralizedSchnorrProofProver generalizedSchnorrProofProver = new GeneralizedSchnorrProofProver();
        GeneralizedSchnorrProofVerifier generalizedSchnorrProofVerifier = new GeneralizedSchnorrProofVerifier();

        GeneralizedSchnorrProof generalizedSchnorrProof = generalizedSchnorrProofProver.generateProof(params, excess.getCommitment(), excess);
        generalizedSchnorrProofVerifier.verify(params, excess.getCommitment(), generalizedSchnorrProof);

        System.out.println("It works");

        System.out.println(System.currentTimeMillis() - start_time);
    }


}
