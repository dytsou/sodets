package gemini

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Request represents the incoming request to the Gemini API endpoint.
// Prompt is optional when a file upload supplies the content instead.
type Request struct {
	Prompt json.RawMessage `json:"prompt"`
}

// GeminiAPIRequest represents the request format for Gemini API
type GeminiAPIRequest struct {
	Contents []Content `json:"contents"`
}

// Content represents a content object in Gemini API request
type Content struct {
	Parts []Part `json:"parts"`
	Role  string `json:"role,omitempty"`
}

// Part represents a part object in Gemini API request
type Part struct {
	Text string `json:"text,omitempty"`
}

// ToGeminiAPIRequest converts a Request to GeminiAPIRequest format
func (r *Request) ToGeminiAPIRequest() GeminiAPIRequest {
	return GeminiAPIRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{
						Text: string(r.Prompt),
					},
				},
			},
		},
	}
}

// Response represents the response from the Gemini API endpoint
type Response struct {
	Text string `json:"text"`
}

// GeminiAPIResponse represents the full response from Gemini API
type GeminiAPIResponse struct {
	Candidates     []Candidate     `json:"candidates"`
	PromptFeedback *PromptFeedback `json:"promptFeedback,omitempty"`
	UsageMetadata  *UsageMetadata  `json:"usageMetadata,omitempty"`
	ModelVersion   string          `json:"modelVersion,omitempty"`
	ResponseID     string          `json:"responseId,omitempty"`
}

// Candidate represents a candidate response from Gemini API
type Candidate struct {
	Content      Content `json:"content"`
	FinishReason string  `json:"finishReason"`
	Index        int     `json:"index"`
}

// PromptFeedback represents feedback about the prompt
type PromptFeedback struct {
	BlockReason   string         `json:"blockReason,omitempty"`
	SafetyRatings []SafetyRating `json:"safetyRatings,omitempty"`
}

// SafetyRating represents a safety rating
type SafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

// UsageMetadata represents token usage information
type UsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// ToResponse converts a GeminiAPIResponse to a simplified Response
func (g *GeminiAPIResponse) ToResponse() Response {
	if len(g.Candidates) > 0 && len(g.Candidates[0].Content.Parts) > 0 {
		return Response{
			Text: g.Candidates[0].Content.Parts[0].Text,
		}
	}
	return Response{
		Text: "",
	}
}

// AnalysisMode represents the classification mode from triage stage
type AnalysisMode string

const (
	ModeClientConfig           AnalysisMode = "MODE_CLIENT_CONFIG"
	ModeDatabaseLogic          AnalysisMode = "MODE_DATABASE_LOGIC"
	ModePerformanceConcurrency AnalysisMode = "MODE_PERFORMANCE_CONCURRENCY"
)

// TriageRequest represents the request for Stage 1 triage analysis
type TriageRequest struct {
	SystemInstruction string `json:"system_instruction"`
	FileContent       string `json:"file_content"`
}

// TriageResponse represents the JSON response from Stage 1 triage
type TriageResponse struct {
	AnalysisMode     AnalysisMode `json:"analysis_mode"`
	DetectedKeywords []string     `json:"detected_keywords"`
	PrimaryErrorLog  string       `json:"primary_error_log"`
}

// ExpertRequest represents the request for Stage 2 expert analysis
type ExpertRequest struct {
	SystemInstruction string `json:"system_instruction"`
	FileContent       string `json:"file_content"`
}

// ExpertResponse represents the response from Stage 2 expert analysis
// This is a free-form text response, not structured JSON
type ExpertResponse struct {
	Text string `json:"text"`
}

// StructuredExpertAnalysis represents a structured expert analysis response
type StructuredExpertAnalysis struct {
	RootCause    RootCauseSection    `json:"root_cause"`
	Verification VerificationSection `json:"verification"`
}

// RootCauseSection contains the root cause analysis
type RootCauseSection struct {
	Category string   `json:"category"`
	Evidence []string `json:"evidence"`
	DeepDive string   `json:"deep_dive"`
}

// VerificationSection contains verification steps
type VerificationSection struct {
	Steps []string `json:"steps"`
}

// AnalyzeLogRequest represents the request for the two-stage log analysis
type AnalyzeLogRequest struct {
	TriagePrompt  string            `json:"triage_prompt" validate:"required"`  // Stage 1 prompt
	ExpertPrompts map[string]string `json:"expert_prompts" validate:"required"` // Stage 2 prompts: key is analysis_mode, value is prompt
	FileContent   string            `json:"file_content" validate:"required"`   // Log file content
}

// ParseTriageResponse attempts to parse a JSON response from the triage stage
// It handles both pure JSON and JSON wrapped in markdown code blocks
func ParseTriageResponse(text string) (*TriageResponse, error) {
	// Remove markdown code blocks if present
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```json") {
		cleaned = strings.TrimPrefix(cleaned, "```json")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	} else if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.TrimPrefix(cleaned, "```")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	}

	var triageResp TriageResponse
	if err := json.Unmarshal([]byte(cleaned), &triageResp); err != nil {
		return nil, err
	}

	return &triageResp, nil
}

// GetExpertPrompt returns the appropriate expert prompt from the provided map based on the analysis mode
func GetExpertPrompt(expertPrompts map[string]string, mode AnalysisMode) (string, error) {
	modeStr := string(mode)
	prompt, exists := expertPrompts[modeStr]
	if !exists {
		return "", fmt.Errorf("expert prompt not found for mode: %s", modeStr)
	}
	return prompt, nil
}

// ParseExpertResponse attempts to parse a structured expert analysis response
// It first tries to parse as JSON (preferred format), then falls back to markdown parsing
func ParseExpertResponse(text string) (*StructuredExpertAnalysis, error) {
	// First, try to parse as JSON (similar to ParseTriageResponse)
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```json") {
		cleaned = strings.TrimPrefix(cleaned, "```json")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	} else if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.TrimPrefix(cleaned, "```")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	}

	// Try JSON parsing first
	var jsonAnalysis StructuredExpertAnalysis
	if err := json.Unmarshal([]byte(cleaned), &jsonAnalysis); err == nil {
		// Validate that we got meaningful data
		if jsonAnalysis.RootCause.Category != "" || len(jsonAnalysis.RootCause.Evidence) > 0 {
			return &jsonAnalysis, nil
		}
	}

	// Fall back to markdown parsing if JSON parsing fails
	return parseExpertResponseMarkdown(text)
}

// parseExpertResponseMarkdown extracts structured data from markdown format (backward compatibility)
func parseExpertResponseMarkdown(text string) (*StructuredExpertAnalysis, error) {
	analysis := &StructuredExpertAnalysis{
		RootCause: RootCauseSection{
			Evidence: []string{},
		},
		Verification: VerificationSection{
			Steps: []string{},
		},
	}

	lines := strings.Split(text, "\n")
	var currentSection string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect section headers
		if strings.HasPrefix(trimmed, "## ") {
			sectionName := strings.TrimPrefix(trimmed, "## ")
			currentSection = sectionName

			if strings.Contains(strings.ToLower(sectionName), "root cause") {
				currentSection = "root_cause"
			} else if strings.Contains(strings.ToLower(sectionName), "verification") || strings.Contains(strings.ToLower(sectionName), "remediation") {
				currentSection = "verification"
			}
			continue
		}

		// Detect subsections within Root Cause
		if currentSection == "root_cause" {
			// Category detection (handles various formats)
			if strings.Contains(trimmed, "**Category:**") {
				category := strings.Split(trimmed, "**Category:**")
				if len(category) > 1 {
					analysis.RootCause.Category = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(category[1]), "-"))
					continue
				}
			}
			// Evidence detection
			if strings.Contains(trimmed, "**Evidence:**") {
				// Evidence items follow on subsequent lines as bullet points
				continue
			}
			// Deep Dive detection
			if strings.Contains(trimmed, "**Deep Dive:**") {
				// Deep dive text follows on subsequent lines until next section or bullet point
				var deepDiveLines []string
				for j := i + 1; j < len(lines); j++ {
					nextLine := strings.TrimSpace(lines[j])
					// Stop at next major section
					if strings.HasPrefix(nextLine, "## ") || (strings.HasPrefix(nextLine, "-   **") && !strings.Contains(nextLine, "Deep Dive")) {
						break
					}
					if nextLine != "" {
						deepDiveLines = append(deepDiveLines, lines[j])
					}
				}
				analysis.RootCause.DeepDive = strings.TrimSpace(strings.Join(deepDiveLines, "\n"))
				continue
			}
			// Collect evidence items (bullet points with various indentations)
			if strings.HasPrefix(trimmed, "    *") || strings.HasPrefix(trimmed, "   *") ||
				(strings.HasPrefix(trimmed, "*") && strings.Contains(trimmed, "trace_id") || strings.Contains(trimmed, "caller")) {
				evidence := trimmed
				// Remove leading spaces and asterisk
				for strings.HasPrefix(evidence, " ") {
					evidence = strings.TrimPrefix(evidence, " ")
				}
				evidence = strings.TrimPrefix(evidence, "*")
				evidence = strings.TrimSpace(evidence)
				if evidence != "" && !strings.Contains(evidence, "**Category:**") &&
					!strings.Contains(evidence, "**Evidence:**") && !strings.Contains(evidence, "**Deep Dive:**") {
					analysis.RootCause.Evidence = append(analysis.RootCause.Evidence, evidence)
				}
				continue
			}
		}

		// Handle Verification section
		if currentSection == "verification" || strings.Contains(strings.ToLower(currentSection), "verification") {
			// Check if we're entering Verification section
			if strings.Contains(strings.ToLower(trimmed), "**verification:**") {
				currentSection = "verification"
				continue
			}
			// Detect numbered verification steps
			if strings.HasPrefix(trimmed, "    1.") || strings.HasPrefix(trimmed, "   1.") ||
				strings.HasPrefix(trimmed, "1.") {
				step := trimmed
				// Remove leading spaces
				for strings.HasPrefix(step, " ") {
					step = strings.TrimPrefix(step, " ")
				}
				// Remove number prefix (1., 2., etc.)
				for i := 1; i <= 9; i++ {
					step = strings.TrimPrefix(step, fmt.Sprintf("%d.", i))
				}
				step = strings.TrimSpace(step)
				if step != "" {
					analysis.Verification.Steps = append(analysis.Verification.Steps, step)
				}
				continue
			}
		}
	}

	// Validate that we extracted meaningful data
	if analysis.RootCause.Category == "" && len(analysis.RootCause.Evidence) == 0 && analysis.RootCause.DeepDive == "" {
		return nil, fmt.Errorf("failed to parse structured data from expert response: no root cause information found")
	}

	return analysis, nil
}

type LogMessage struct {
	Caller string `json:"caller"`
}
type Details struct {
	Message string `json:"message"`
}
type TimelineEntry struct {
	Details *Details `json:"details"`
}
type Incident struct {
	Timeline []interface{} `json:"timeline"`
}
