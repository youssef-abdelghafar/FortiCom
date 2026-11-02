"""AI layer: Isolation Forest (scikit-learn) with a fast single-sample scorer.

scikit-learn needs ~3 ms to score ONE sample (thread/joblib overhead). A streaming
receiver sees one message at a time, so after fitting we copy the trees into plain
Python lists and walk them ourselves (~0.1 ms per sample). selftest.py checks that the
scores are identical to scikit-learn's.
"""
import warnings
import numpy as np
from sklearn.ensemble import IsolationForest


def _c(n):
    """Average path length of an unsuccessful search in a binary tree (iForest paper)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (np.log(n - 1) + np.euler_gamma) - 2.0 * (n - 1) / n


class FastIForest:
    def __init__(self, n_estimators=60, max_samples=256, seed=0):
        self.n, self.ms, self.seed = n_estimators, max_samples, seed

    def fit(self, X):
        m = IsolationForest(n_estimators=self.n, max_samples=min(self.ms, len(X)),
                            random_state=self.seed, n_jobs=1).fit(X)
        self._m, self.cpsi, self.trees = m, _c(m.max_samples_), []
        for est in m.estimators_:
            t = est.tree_
            L, R = t.children_left.tolist(), t.children_right.tolist()
            F, T = t.feature.tolist(), t.threshold.tolist()
            depth, leaf, stack = [0] * t.node_count, [0.0] * t.node_count, [0]
            while stack:
                i = stack.pop()
                if L[i] == -1:      # leaf: depth + expected extra depth for the samples left in it
                    leaf[i] = depth[i] + _c(int(t.n_node_samples[i]))
                else:
                    depth[L[i]] = depth[R[i]] = depth[i] + 1
                    stack += [L[i], R[i]]
            self.trees.append((L, R, F, T, leaf))
        return self

    def score1(self, x):
        """Anomaly score in (0, 1): higher = more anomalous."""
        tot = 0.0
        for L, R, F, T, leaf in self.trees:
            i = 0
            while L[i] != -1:
                i = L[i] if x[F[i]] <= T[i] else R[i]
            tot += leaf[i]
        return 2.0 ** (-(tot / len(self.trees)) / self.cpsi)

    def score(self, X):
        return np.array([self.score1(x) for x in X])


class FastAutoencoder:
    """Small neural autoencoder (7 -> 8 -> 3 -> 8 -> 7, tanh) trained on CLEAN features only.
    Anomaly score = reconstruction error. Unlike Isolation Forest, the error keeps growing
    for values far outside the training range, so large biases are still caught.
    Inference is a few tiny matrix products in numpy (no scikit-learn call per message)."""

    def __init__(self, hidden=(8, 3, 8), seed=0):
        self.hidden, self.seed = hidden, seed

    def fit(self, X):
        from sklearn.neural_network import MLPRegressor
        X = np.asarray(X, float)
        self.m, self.s = X.mean(0), X.std(0)
        self.s[self.s < 1e-9] = 1.0
        Z = (X - self.m) / self.s
        with warnings.catch_warnings():           # stops after 800 epochs; good enough here
            warnings.simplefilter("ignore")
            net = MLPRegressor(hidden_layer_sizes=self.hidden, activation="tanh", max_iter=800,
                               random_state=self.seed, early_stopping=False).fit(Z, Z)
        self.W, self.b = net.coefs_, net.intercepts_
        return self

    def score1(self, x):
        a = (np.asarray(x, float) - self.m) / self.s
        z = a
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            z = z @ W + b
            if i < len(self.W) - 1:
                z = np.tanh(z)
        return float(np.mean((z - a) ** 2))

    def score(self, X):
        return np.array([self.score1(x) for x in X])
