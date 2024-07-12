**Scoring Formula**:

It is just for exploratory purposes, not based on anything

$32y_t + 8y_p + 0.04y_i + \sum_{s \in B} Q(s_{\text{confidence}}) \times P(s_{\text{severity}})$

- $y_t :=$ yara tests failed
- $y_p :=$ yara matches
- $y_i :=$ yara matched instances (specific strings/bytes)
- $B :=$ set of failed bandit tests
- $P(\text{high}) = 1$
- $P(\text{medium}) = 0.8$
- $P(\text{low}) = 0.6$
- $Q(\text{high}) = 10$
- $Q(\text{medium}) = 3$
- $Q(\text{low}) = 0.16$