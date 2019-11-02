package Lasse_Herskind;

import Lasse_Herskind.OneOutOfMany.OneOutOfManyProof;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyWitness;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyWitnessMW;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class LelantusUtils<T extends GroupElement<T>> {


    public static DoubleBlindedPedersenCommitment getDBPedersen(DoubleGeneratorParams params, BigInteger serial, BigInteger value, BigInteger r2) {
        return new DoubleBlindedPedersenCommitment(params.getBase(), serial, value, r2);
    }

    public static DoubleBlindedPedersenCommitment getDBPedersen(DoubleGeneratorParams params, BigInteger value) {
        return new DoubleBlindedPedersenCommitment(params.getBase(), value);
    }


    public static BigInteger getChallenge(DoubleGeneratorParams params, OneOutOfManyProof proof) {
        return ProofUtils.computeChallenge(params.getGroup().groupOrder());//, proof.getA(), proof.getB(), proof.getC(), proof.getD());
    }


    public static GroupElement getAPublic(DoubleGeneratorParams params, BigInteger V, OneOutOfManyProof... proofs) {
        int m = LelantusConstants.m;

        GroupElement[] Qks = proofs[0].getQks();
        BigInteger x = getChallenge(params, proofs[0]);
        GroupElement public_A = getDBPedersen(params, BigInteger.ZERO, proofs[0].getzV(), proofs[0].getzR()).getCommitment();
        for (int k = 0; k < m; k++) {
            public_A = public_A.add(Qks[k].multiply(x.pow(k)));
        }

        for (int i = 1; i < proofs.length; i++) {
            Qks = proofs[i].getQks();
            x = getChallenge(params, proofs[i]);
            GroupElement public_A_Temp = getDBPedersen(params, BigInteger.ZERO, proofs[i].getzV(), proofs[i].getzR()).getCommitment();
            for (int k = 0; k < m; k++) {
                public_A_Temp = public_A_Temp.add(Qks[k].multiply(x.pow(k)));
            }
            public_A = public_A.add(public_A_Temp);
        }

        public_A = public_A.subtract(getDBPedersen(params, BigInteger.ZERO, V.multiply(x.pow(m)), BigInteger.ZERO).getCommitment());

        return public_A;
    }

    public static BigInteger getAPrivate(DoubleGeneratorParams params, OneOutOfManyProof proof, OneOutOfManyWitness witness) {
        int m = LelantusConstants.m;

        BigInteger x = getChallenge(params, proof);
        BigInteger[] gammak = witness.getGammaK();

        BigInteger witness_a = witness.getR().multiply(x.pow(m));
        for (int k = 0; k < m; k++) {
            witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
        }
        witness_a.mod(params.getGroup().groupOrder());
        return witness_a;
    }

    public static BigInteger getAPrivateMultiple(DoubleGeneratorParams params, OneOutOfManyProof[] proofs, OneOutOfManyWitness[] witnesses) {
        int m = LelantusConstants.m;

        BigInteger x = getChallenge(params, proofs[0]);
        BigInteger[] gammak = witnesses[0].getGammaK();

        BigInteger witness_a = witnesses[0].getR().multiply(x.pow(m));
        for (int k = 0; k < m; k++) {
            witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
        }

        for (int i = 1; i < proofs.length; i++) {
            x = getChallenge(params, proofs[i]);
            gammak = witnesses[i].getGammaK();

            witness_a = witness_a.add(witnesses[i].getR().multiply(x.pow(m)));
            for (int k = 0; k < m; k++) {
                witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
            }
        }
        witness_a = witness_a.mod(params.getGroup().groupOrder());

        return witness_a;
    }


    // --------------------------------------
    // --MimbleWimble Utils below this line--
    // --------------------------------------


    public static BigInteger getChallenge(DoubleGeneratorParams params, OneOutOfManyProofMW proof) {
        return ProofUtils.computeChallenge(params.getGroup().groupOrder());//, proof.getA(), proof.getB(), proof.getC(), proof.getD());
    }

    public static GroupElement getAPublic(DoubleGeneratorParams params, OneOutOfManyProofMW... proofs) {
        int m = LelantusConstants.m;

        GroupElement[] Qks = proofs[0].getQks();
        BigInteger x = getChallenge(params, proofs[0]);
        GroupElement public_A = getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, proofs[0].getzR()).getCommitment();
        for (int k = 0; k < m; k++) {
            public_A = public_A.add(Qks[k].multiply(x.pow(k)));
        }

        for (int i = 1; i < proofs.length; i++) {
            Qks = proofs[i].getQks();
            x = getChallenge(params, proofs[i]);
            GroupElement public_A_Temp = getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, proofs[i].getzR()).getCommitment();
            for (int k = 0; k < m; k++) {
                public_A_Temp = public_A_Temp.add(Qks[k].multiply(x.pow(k)));
            }
            public_A = public_A.add(public_A_Temp);
        }

        return public_A;
    }

    public static BigInteger getAPrivate(DoubleGeneratorParams params, OneOutOfManyProofMW proof, OneOutOfManyWitnessMW witness) {
        int m = LelantusConstants.m;

        BigInteger x = getChallenge(params, proof);
        BigInteger[] gammak = witness.getGammaK();

        BigInteger witness_a = witness.getR().multiply(x.pow(m));
        for (int k = 0; k < m; k++) {
            witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
        }
        witness_a.mod(params.getGroup().groupOrder());
        return witness_a;
    }

    public static BigInteger getAPrivateMultiple(DoubleGeneratorParams params, OneOutOfManyProofMW[] proofs, OneOutOfManyWitnessMW[] witnesses) {
        int m = LelantusConstants.m;

        BigInteger x = getChallenge(params, proofs[0]);
        BigInteger[] gammak = witnesses[0].getGammaK();

        BigInteger witness_a = witnesses[0].getR().multiply(x.pow(m));
        for (int k = 0; k < m; k++) {
            witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
        }

        for (int i = 1; i < proofs.length; i++) {
            x = getChallenge(params, proofs[i]);
            gammak = witnesses[i].getGammaK();

            witness_a = witness_a.add(witnesses[i].getR().multiply(x.pow(m)));
            for (int k = 0; k < m; k++) {
                witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
            }
        }
        witness_a = witness_a.mod(params.getGroup().groupOrder());

        return witness_a;
    }


}
