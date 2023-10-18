package watchdog

import (
	"regexp"

	geo "github.com/kellydunn/golang-geo"
)

var geofenceRegexp = regexp.MustCompile(`^([-+]?[0-9]*\.?[0-9]+)[^-+0-9]+([-+]?[0-9]*\.?[0-9]+)(?:[^0-9]+([0-9]*\.?[0-9]+)([A-Za-z]*)[^0-9]*)?$`)
var geofenceUnits = map[string]float64{
	"":   1.0,
	"m":  1.0,
	"km": 1000.0,
	"mi": 1609.0,
	"ft": 1609.0 / 5280.0,
}

// Geofence 代表地球上的一个点，其精确半径以米为单位
type Geofence struct {
	Type                        GeofenceType
	Field                       string
	Value                       string
	Latitude, Longitude, Radius float64
}

type GeofenceType string

const (
	Location  GeofenceType = "Location"
	Parameter              = "Parameter"
)

// SetIntersection 是对两个集合之间关系的描述
type SetIntersection uint

const (
	// IsDisjoint 表示两个集合没有共同元素
	IsDisjoint SetIntersection = 1 << iota

	// IsSubset 表示第一个集合是第二个集合的子集
	IsSubset

	// IsSuperset 表示第一个集合是第二个集合的超集
	IsSuperset
)

// Intersection 代表两个地理点之间的关系
func (mi *Geofence) Intersection(tu *Geofence) (i SetIntersection) {
	miPoint := geo.NewPoint(mi.Latitude, mi.Longitude)
	tuPoint := geo.NewPoint(tu.Latitude, tu.Longitude)
	// miPoint 与 tuPoint 的地球间距离
	distance := miPoint.GreatCircleDistance(tuPoint) * 1000

	radiusSum := mi.Radius + tu.Radius
	radiusDiff := mi.Radius - tu.Radius

	if distance-radiusSum > 0 {
		i = IsDisjoint
		return
	}

	if -distance+radiusDiff >= 0 {
		i |= IsSuperset
	}

	if -distance-radiusDiff >= 0 {
		i |= IsSubset
	}

	return
}
