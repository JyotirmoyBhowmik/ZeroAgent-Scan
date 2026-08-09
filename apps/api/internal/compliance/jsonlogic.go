package compliance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// EvaluateExpression parses a JSONLogic expression string and evaluates it against data.
func EvaluateExpression(exprJSON string, data interface{}) (bool, error) {
	if strings.TrimSpace(exprJSON) == "" {
		return true, nil
	}

	var parsedExpr interface{}
	if err := json.Unmarshal([]byte(exprJSON), &parsedExpr); err != nil {
		return false, fmt.Errorf("jsonlogic: invalid JSON expression: %w", err)
	}

	// If data is a struct or byte slice, convert to map[string]interface{}
	normalizedData, err := normalizeData(data)
	if err != nil {
		return false, fmt.Errorf("jsonlogic: failed to normalize data payload: %w", err)
	}

	res, err := evalNode(parsedExpr, normalizedData)
	if err != nil {
		return false, err
	}

	return isTruthy(res), nil
}

// ExtractValue retrieves and stringifies a value from data using dot-notation path.
func ExtractValue(data interface{}, path string) string {
	normalized, err := normalizeData(data)
	if err != nil {
		return "<error>"
	}

	val := resolveVar(normalized, path)
	if val == nil {
		return "<null>"
	}

	switch v := val.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', 2, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		b, err := json.Marshal(v)
		if err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", v)
	}
}

func normalizeData(data interface{}) (map[string]interface{}, error) {
	if m, ok := data.(map[string]interface{}); ok {
		return m, nil
	}

	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func evalNode(node interface{}, data map[string]interface{}) (interface{}, error) {
	// Base literal values
	switch v := node.(type) {
	case bool, float64, string, nil:
		return v, nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case []interface{}:
		var evaluatedList []interface{}
		for _, item := range v {
			ev, err := evalNode(item, data)
			if err != nil {
				return nil, err
			}
			evaluatedList = append(evaluatedList, ev)
		}
		return evaluatedList, nil
	case map[string]interface{}:
		// JSONLogic Operator node
		for op, args := range v {
			return applyOperator(op, args, data)
		}
	}

	return false, fmt.Errorf("jsonlogic: unsupported AST node: %T", node)
}

func applyOperator(op string, args interface{}, data map[string]interface{}) (interface{}, error) {
	switch op {
	case "var":
		path := ""
		if s, ok := args.(string); ok {
			path = s
		} else if list, ok := args.([]interface{}); ok && len(list) > 0 {
			if s, ok := list[0].(string); ok {
				path = s
			}
		}
		return resolveVar(data, path), nil

	case "==", "===":
		list, ok := args.([]interface{})
		if !ok || len(list) < 2 {
			return false, fmt.Errorf("jsonlogic: '==' requires 2 arguments")
		}
		left, err := evalNode(list[0], data)
		if err != nil {
			return false, err
		}
		right, err := evalNode(list[1], data)
		if err != nil {
			return false, err
		}
		return compareEqual(left, right), nil

	case "!=", "!==":
		list, ok := args.([]interface{})
		if !ok || len(list) < 2 {
			return false, fmt.Errorf("jsonlogic: '!=' requires 2 arguments")
		}
		left, err := evalNode(list[0], data)
		if err != nil {
			return false, err
		}
		right, err := evalNode(list[1], data)
		if err != nil {
			return false, err
		}
		return !compareEqual(left, right), nil

	case "<":
		return compareNumeric(args, data, func(a, b float64) bool { return a < b })
	case "<=":
		return compareNumeric(args, data, func(a, b float64) bool { return a <= b })
	case ">":
		return compareNumeric(args, data, func(a, b float64) bool { return a > b })
	case ">=":
		return compareNumeric(args, data, func(a, b float64) bool { return a >= b })

	case "in":
		list, ok := args.([]interface{})
		if !ok || len(list) < 2 {
			return false, fmt.Errorf("jsonlogic: 'in' requires [item, collection]")
		}
		target, err := evalNode(list[0], data)
		if err != nil {
			return false, err
		}
		collection, err := evalNode(list[1], data)
		if err != nil {
			return false, err
		}
		return checkIn(target, collection), nil

	case "and":
		list, ok := args.([]interface{})
		if !ok {
			return false, fmt.Errorf("jsonlogic: 'and' requires array of expressions")
		}
		for _, item := range list {
			res, err := evalNode(item, data)
			if err != nil {
				return false, err
			}
			if !isTruthy(res) {
				return false, nil
			}
		}
		return true, nil

	case "or":
		list, ok := args.([]interface{})
		if !ok {
			return false, fmt.Errorf("jsonlogic: 'or' requires array of expressions")
		}
		for _, item := range list {
			res, err := evalNode(item, data)
			if err != nil {
				return false, err
			}
			if isTruthy(res) {
				return true, nil
			}
		}
		return false, nil

	case "!", "not":
		var target interface{}
		if list, ok := args.([]interface{}); ok && len(list) > 0 {
			target = list[0]
		} else {
			target = args
		}
		res, err := evalNode(target, data)
		if err != nil {
			return false, err
		}
		return !isTruthy(res), nil
	}

	return false, fmt.Errorf("jsonlogic: unsupported operator '%s'", op)
}

func resolveVar(data map[string]interface{}, path string) interface{} {
	if path == "" {
		return data
	}

	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		if current == nil {
			return nil
		}

		switch node := current.(type) {
		case map[string]interface{}:
			current = node[part]
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err == nil && idx >= 0 && idx < len(node) {
				current = node[idx]
			} else {
				return nil
			}
		default:
			return nil
		}
	}

	return current
}

func compareEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Try numeric coercion
	numA, isNumA := toFloat(a)
	numB, isNumB := toFloat(b)
	if isNumA && isNumB {
		return numA == numB
	}

	// Try slice / map deep equality
	valA := reflect.ValueOf(a)
	valB := reflect.ValueOf(b)
	if valA.Kind() == reflect.Slice && valB.Kind() == reflect.Slice {
		if valA.Len() == 0 && valB.Len() == 0 {
			return true
		}
		return reflect.DeepEqual(a, b)
	}

	return reflect.DeepEqual(a, b)
}

func compareNumeric(args interface{}, data map[string]interface{}, cmp func(a, b float64) bool) (bool, error) {
	list, ok := args.([]interface{})
	if !ok || len(list) < 2 {
		return false, fmt.Errorf("jsonlogic: numeric comparison requires 2 arguments")
	}

	left, err := evalNode(list[0], data)
	if err != nil {
		return false, err
	}
	right, err := evalNode(list[1], data)
	if err != nil {
		return false, err
	}

	numA, okA := toFloat(left)
	numB, okB := toFloat(right)
	if !okA || !okB {
		return false, nil
	}

	return cmp(numA, numB), nil
}

func checkIn(target, collection interface{}) bool {
	if collection == nil || target == nil {
		return false
	}

	targetStr := strings.ToLower(fmt.Sprintf("%v", target))

	switch col := collection.(type) {
	case string:
		return strings.Contains(strings.ToLower(col), targetStr)
	case []interface{}:
		for _, item := range col {
			if compareEqual(target, item) {
				return true
			}
		}
	case []string:
		for _, item := range col {
			if strings.EqualFold(targetStr, strings.ToLower(item)) {
				return true
			}
		}
	}

	return false
}

func isTruthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case float64:
		return val != 0
	case int:
		return val != 0
	case int64:
		return val != 0
	case string:
		return val != "" && val != "false" && val != "0"
	case []interface{}:
		return len(val) > 0
	case map[string]interface{}:
		return len(val) > 0
	}
	return false
}

func toFloat(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	}
	return 0, false
}
