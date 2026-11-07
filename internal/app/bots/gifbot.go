package bots

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"go.uber.org/zap"

	"telesrv/internal/domain"
	"telesrv/internal/seed/catalog"
)

// HandlesInlineBot reports whether botUserID is a built-in bot this service
// answers messages.getInlineBotResults for synchronously
// (rpc.ServiceBotInlineResults). Deliberately separate from HandlesBot (see
// that interface's doc comment in internal/rpc/deps.go) -- @gif gets inline
// queries only, not private-message/callback dispatch.
func (s *Service) HandlesInlineBot(botUserID int64) bool {
	return s != nil && botUserID == domain.GifBotUserID
}

// OnInlineQuery serves @gif's admin-curated catalog as inline gif results,
// ordered by title relevance to query (see rankGifCatalogEntries) or, for a
// category-icon tap, filtered to that category (see gifCategoryFromQuery).
//
// offset/paging is not implemented: filtering/ranking runs over the whole
// catalog (an operator's library can run into the thousands, see
// files.Service.ListGifCatalog's doc comment for why that fetch is
// deliberately unbounded), then the result is truncated to
// MaxGifCatalogEntries -- the real per-response cap the client enforces --
// so one response always carries as much of the *relevant* slice as fits,
// not an arbitrary (sort_order, id) prefix of the whole catalog.
//
// Note TDesktop only ever calls this with a non-empty query: its GIF tab has
// no trending panel, and GifsListWidget::searchForGifs returns early on an
// empty string (chat_helpers/gifs_list_widget.cpp), showing saved GIFs alone.
// An empty query is still handled here for clients that do ask for one.
func (s *Service) OnInlineQuery(ctx context.Context, botUserID, _ int64, query, _ string) (domain.BotInlineResults, bool, error) {
	if s == nil || botUserID != domain.GifBotUserID {
		return domain.BotInlineResults{}, false, nil
	}
	if s.gifCatalog == nil {
		return domain.BotInlineResults{Gallery: true}, true, nil
	}
	entries, err := s.gifCatalog.ListGifCatalog(ctx, true)
	if err != nil {
		return domain.BotInlineResults{}, false, err
	}
	category := gifCategoryFromQuery(query)
	if category != "" {
		// A category-icon tap, not a typed word (see gifCategoryFromQuery) --
		// filter by domain.GifCatalogEntry.Category instead of ranking by
		// title, since the query is an emoji/emoji-blob a title never
		// contains.
		entries = filterGifCatalogEntriesByCategory(entries, category)
	} else {
		entries = rankGifCatalogEntries(entries, query)
	}
	if s.log != nil {
		s.log.Info("gif inline query",
			zap.String("query", query), zap.String("detected_category", category),
			zap.Int("result_count", len(entries)))
	}
	if len(entries) == 0 {
		return domain.BotInlineResults{Gallery: true}, true, nil
	}
	if len(entries) > domain.MaxGifCatalogEntries {
		entries = entries[:domain.MaxGifCatalogEntries]
	}
	ids := make([]int64, len(entries))
	for i, e := range entries {
		ids[i] = e.DocumentID
	}
	docs, err := s.gifCatalog.GetDocuments(ctx, ids)
	if err != nil {
		return domain.BotInlineResults{}, false, err
	}
	byID := make(map[int64]domain.Document, len(docs))
	for _, d := range docs {
		byID[d.ID] = d
	}
	for _, entry := range entries {
		if _, ok := byID[entry.DocumentID]; !ok {
			return domain.BotInlineResults{}, false, fmt.Errorf("gif catalog entry %d references missing document %d", entry.ID, entry.DocumentID)
		}
	}
	results := make([]domain.BotInlineResult, 0, len(entries))
	for _, e := range entries {
		doc, ok := byID[e.DocumentID]
		if !ok {
			return domain.BotInlineResults{}, false, fmt.Errorf("gif catalog entry %d references missing document %d", e.ID, e.DocumentID)
		}
		docCopy := doc
		results = append(results, domain.BotInlineResult{
			ID:    strconv.FormatInt(e.ID, 10),
			Type:  "gif",
			Title: e.Title,
			Media: &domain.MessageMedia{Kind: domain.MessageMediaKindDocument, Document: &docCopy},
		})
	}
	return domain.BotInlineResults{Gallery: true, Results: results}, true, nil
}

// rankGifCatalogEntries orders title matches first but never drops the rest.
//
// A real @gif searches a huge third-party index, so "no match" there means the
// query genuinely found nothing. A self-hosted catalog is a handful of curated
// files instead: filtering it down to exact title matches would leave the
// picker empty for almost every word an operator's users type, which reads as
// "the feature is broken" rather than "no results". Showing the whole catalog
// with the closest titles first keeps every query useful while still honouring
// the search term. Order within each group stays the admin-set
// (sort_order, id) order the store already applied.
// gifCategoryFromQuery recognizes a GIF-picker category-icon tap and returns
// which domain.GifCatalogCategories entry it names, or "" for an ordinary
// typed search. Neither client sends the category's name -- both instead
// send the tapped group's own Emoticons back as the query, observed (see
// the "gif inline query" log line this handler emits) to differ only in
// whitespace between clients: Android sends them concatenated with no
// separator, TDesktop space-separated. Comparing with all whitespace
// stripped from the query handles both without caring which client asked,
// and is why this checks against internal/seed/catalog data directly (the
// same source messages.getEmojiGroups itself serves) rather than hardcoding
// either shape.
func gifCategoryFromQuery(query string) string {
	stripped := stripWhitespace(query)
	if stripped == "" {
		return ""
	}
	groups, _ := catalog.EmojiGroups()
	for _, g := range groups {
		if len(g.Emoticons) == 0 {
			continue
		}
		if strings.Join(g.Emoticons, "") == stripped {
			return g.Title
		}
	}
	for _, g := range groups {
		for _, e := range g.Emoticons {
			if e == stripped {
				return g.Title
			}
		}
	}
	return ""
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// filterGifCatalogEntriesByCategory keeps only entries tagged with category,
// falling back to the full (enabled) catalog if none are tagged yet -- an
// operator who hasn't categorized anything should still see every GIF on a
// category tap, not an empty picker.
func filterGifCatalogEntriesByCategory(entries []domain.GifCatalogEntry, category string) []domain.GifCatalogEntry {
	filtered := make([]domain.GifCatalogEntry, 0, len(entries))
	for _, e := range entries {
		if e.Category == category {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		return entries
	}
	return filtered
}

func rankGifCatalogEntries(entries []domain.GifCatalogEntry, query string) []domain.GifCatalogEntry {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return entries
	}
	matched := make([]domain.GifCatalogEntry, 0, len(entries))
	rest := make([]domain.GifCatalogEntry, 0, len(entries))
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Title), query) {
			matched = append(matched, e)
		} else {
			rest = append(rest, e)
		}
	}
	return append(matched, rest...)
}
