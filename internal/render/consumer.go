package render

import "github.com/cybericebox/icevault/internal/model"

// Project implements model.Consumer: the rules a Store asks of the project.
var _ model.Consumer = (*Project)(nil)

// Normalize: an owner placeholder is an empty value.
func (p *Project) Normalize(value, managed string) string { return StoredValue(value, managed) }

// CheckLabels accepts every label set (the project gives no label a meaning of its own).
func (p *Project) CheckLabels([]string, string) error { return nil }

// KeyVisibility is the rule's visibility for a new variable of that key.
func (p *Project) KeyVisibility(key string) string { return p.ProposedVisibility(key) }

// ScopeOf is "block" or "environment" (see EntryScope).
func (p *Project) ScopeOf(e *model.Entry) string { return p.EntryScope(e) }

// RelsOf are the settings files an entry renders into.
func (p *Project) RelsOf(e *model.Entry) []string { return p.EntryRels(e, nil) }

// EnvGroup is the group an environment-wide entry lives in: its own.
func (p *Project) EnvGroup(group, _ string) string { return group }

// BlockRels are the settings files that list the key.
func (p *Project) BlockRels(key string) []string { return p.KeyFiles(key) }

// BlockGroup is the group a block entry of rel lives in.
func (p *Project) BlockGroup(rel, _ string) string { return GroupOf(rel) }

// BlockLabel is the label that narrows an entry to rel.
func (p *Project) BlockLabel(rel string) string { return LabelFile + rel }

// StripBlock removes the file: labels.
func (p *Project) StripBlock(labels []string) []string { return StripBlock(labels) }

// ChecklistRows adapts Checklist for the Store; ok is false when it cannot be computed.
func (p *Project) ChecklistRows(snap *model.Snapshot, env, site string) ([]model.CheckRow, bool) {
	c, err := p.Checklist(snap, env, site)
	if err != nil {
		return nil, false
	}
	rows := make([]model.CheckRow, 0, len(c.Rows))
	for _, r := range c.Rows {
		cr := model.CheckRow{Key: r.Key, File: r.File, State: r.State, Required: r.Required}
		if r.Create != nil {
			cr.Create = &model.CreateSpec{Key: r.Create.Key, Group: r.Create.Group, Description: r.Create.Description, Visibility: r.Create.Visibility, Labels: r.Create.Labels}
		}
		rows = append(rows, cr)
	}
	return rows, true
}
