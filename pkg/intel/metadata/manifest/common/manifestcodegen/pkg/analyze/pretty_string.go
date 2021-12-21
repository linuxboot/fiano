// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analyze

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/fatih/camelcase"
)

func getPrettyString(typ ast.Expr, doc, comment *ast.CommentGroup, docPrefix string) (string, error) {
	if doc == nil {
		doc = comment
	}

	if doc != nil {
		for _, docItem := range doc.List {
			text := strings.TrimSpace(strings.TrimLeft(docItem.Text, "/"))
			if !strings.HasPrefix(text, docPrefix) {
				continue
			}

			return strings.TrimSpace(text[len(docPrefix):]), nil
		}
	}

	if ident, ok := typ.(*ast.Ident); ok {
		return strings.Join(camelcase.Split(ident.Name), " "), nil
	}

	if doc != nil {
		if len(doc.List) > 0 {
			return strings.TrimSpace(strings.TrimLeft(doc.List[0].Text, "/")), nil
		}
	}

	return "", fmt.Errorf("comment with prefix '%s' is not found", docPrefix)
}
