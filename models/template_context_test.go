package models

import (
	"fmt"

	check "gopkg.in/check.v1"
)

type mockTemplateContext struct {
	URL         string
	FromAddress string
}

func (m mockTemplateContext) getFromAddress() string {
	return m.FromAddress
}

func (m mockTemplateContext) getBaseURL() string {
	return m.URL
}

func (s *ModelsSuite) TestNewTemplateContext(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "Foo",
			LastName:  "Bar",
			Email:     "foo@bar.com",
		},
		Post_Id: "1234567",
	}
	ctx := mockTemplateContext{
		URL:         "http://example.com",
		FromAddress: "From Address <from@example.com>",
	}
	expected := PhishingTemplateContext{
		URL:           fmt.Sprintf("%s?Post_Id=%s", ctx.URL, r.Post_Id),
		BaseURL:       ctx.URL,
		BaseRecipient: r.BaseRecipient,
		TrackingURL:   fmt.Sprintf("%s/follow?Post_Id=%s", ctx.URL, r.Post_Id),
		From:          "From Address",
		Post_Id:       r.Post_Id,
	}
	expected.Tracker = "<img alt='' style='display: none' src='" + expected.TrackingURL + "'/>"
	got, err := NewPhishingTemplateContext(ctx, r.BaseRecipient, r.Post_Id)
	c.Assert(err, check.Equals, nil)
	c.Assert(got, check.DeepEquals, expected)
}
