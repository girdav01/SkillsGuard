package intelligence

import (
	"sync"
	"time"
)

// CommunityVerdict represents a single community verdict submission.
type CommunityVerdict struct {
	Verdict   string    `json:"verdict"`
	Analyst   string    `json:"analyst"`
	Timestamp time.Time `json:"timestamp"`
}

// CommunityComment represents a community comment.
type CommunityComment struct {
	Author    string    `json:"author"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

// SkillReputation is the community reputation for a skill.
type SkillReputation struct {
	SHA256          string             `json:"sha256"`
	Verdicts        []CommunityVerdict `json:"verdicts"`
	Comments        []CommunityComment `json:"comments"`
	ConsensusVerdict string            `json:"consensus_verdict"`
	TotalVotes      int                `json:"total_votes"`
}

// CommunityVerdicts manages community-sourced verdicts.
type CommunityVerdicts struct {
	mu          sync.RWMutex
	verdicts    map[string][]CommunityVerdict
	comments    map[string][]CommunityComment
}

// NewCommunityVerdicts creates a new CommunityVerdicts.
func NewCommunityVerdicts() *CommunityVerdicts {
	return &CommunityVerdicts{
		verdicts: make(map[string][]CommunityVerdict),
		comments: make(map[string][]CommunityComment),
	}
}

// AddVerdict adds a community verdict for a skill hash.
func (c *CommunityVerdicts) AddVerdict(sha256, verdict, analyst string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verdicts[sha256] = append(c.verdicts[sha256], CommunityVerdict{
		Verdict:   verdict,
		Analyst:   analyst,
		Timestamp: time.Now().UTC(),
	})
}

// AddComment adds a community comment for a skill hash.
func (c *CommunityVerdicts) AddComment(sha256, author, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.comments[sha256] = append(c.comments[sha256], CommunityComment{
		Author:    author,
		Text:      text,
		Timestamp: time.Now().UTC(),
	})
}

// GetReputation returns the community reputation for a skill hash.
func (c *CommunityVerdicts) GetReputation(sha256 string) SkillReputation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	verdicts := c.verdicts[sha256]
	comments := c.comments[sha256]

	if verdicts == nil {
		verdicts = []CommunityVerdict{}
	}
	if comments == nil {
		comments = []CommunityComment{}
	}

	consensus := computeConsensus(verdicts)

	return SkillReputation{
		SHA256:           sha256,
		Verdicts:         verdicts,
		Comments:         comments,
		ConsensusVerdict: consensus,
		TotalVotes:       len(verdicts),
	}
}

func computeConsensus(verdicts []CommunityVerdict) string {
	if len(verdicts) == 0 {
		return "unknown"
	}
	counts := make(map[string]int)
	for _, v := range verdicts {
		counts[v.Verdict]++
	}
	best := ""
	bestCount := 0
	for verdict, count := range counts {
		if count > bestCount {
			bestCount = count
			best = verdict
		}
	}
	return best
}
