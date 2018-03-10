package Lasse_Herskind.TransactionBalancesKnowledgeProof;

import ch.qos.logback.core.net.SyslogOutputStream;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;

public class TransactionProofProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, T, PeddersenCommitment<T>, TransactionProof<T>> {
    @Override
    public TransactionProof<T> generateProof(GeneratorParams<T> parameter, T input, PeddersenCommitment<T> witness) {
        System.out.println("Transaction Proof");


        return null;
    }
}
