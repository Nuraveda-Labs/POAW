"""Node-store proofs must equal the brute-force RFC 6962 tree, and consistency proofs must verify only when honest."""
import poaw_core as p

LEAVES = [p.sha256(bytes([i, i >> 8])) for i in range(80)]


def store_for(n):
    nodes = {}
    for i in range(n):
        for lvl, idx, h in p.nodes_completed_by(i, LEAVES[i], lambda l, j: nodes[(l, j)]):
            nodes[(lvl, idx)] = h
    return nodes


def test_node_store_matches_brute_force_everywhere():
    for n in range(1, 65):
        nodes = store_for(n)
        get = lambda l, j: nodes[(l, j)]
        assert p.mth_range(0, n, get) == p.mth(LEAVES[:n])
        for i in range(n):
            assert p.inclusion_path_nodes(i, n, get) == p.inclusion_path(i, LEAVES[:n])


def test_consistency_proofs_verify_and_reject_tampering():
    for n in range(1, 65):
        nodes = store_for(n)
        get = lambda l, j: nodes[(l, j)]
        new_root = p.mth(LEAVES[:n])
        for m in range(1, n + 1):
            proof = p.consistency_proof_nodes(m, n, get)
            assert proof == p.consistency_proof(m, n, LEAVES)
            old_root = p.mth(LEAVES[:m])
            assert p.verify_consistency(m, n, old_root, new_root, proof), (m, n)
            if m < n:
                assert not p.verify_consistency(m, n, p.sha256(b"forged"), new_root, proof)
                assert not p.verify_consistency(m, n, old_root, p.sha256(b"forged"), proof)
                if proof:
                    bad = proof[:]; bad[0] = p.sha256(b"x")
                    assert not p.verify_consistency(m, n, old_root, new_root, bad)


def test_a_fork_is_detected():
    forked = LEAVES[:10] + [p.sha256(b"rewritten history")] + LEAVES[11:20]
    honest_old = p.mth(LEAVES[:12])
    proof = p.consistency_proof(12, 20, forked)
    assert not p.verify_consistency(12, 20, honest_old, p.mth(forked), proof)
