// Map + attack-arc rendering. The dashboard overlay lives in overlay.js and
// receives events via the "attack" / "ws-status" CustomEvents dispatched at
// the bottom of this file.

if (!window.MAPBOX_TOKEN) {
    console.warn("MAPBOX_TOKEN is not set; map tiles will not render. Set the MAPBOX_TOKEN env var on AttackMapServer.");
}

// Lock the map to the world's vertical extent: maxBounds (with full
// viscosity) hard-stops drags at the top/bottom poles, while longitude is
// left effectively unbounded so horizontal panning still wraps freely.
var WORLD_LAT = 85.0511; // Web-Mercator latitude limit
var map = L.map("map", {
    center: [0, 0],
    zoom: 2,
    zoomControl: false,
    maxBounds: [[-WORLD_LAT, -1e6], [WORLD_LAT, 1e6]],
    maxBoundsViscosity: 1.0
});

// Keep the world at least as tall as the viewport (world height in CSS px is
// 256 * 2^zoom), so zooming out can never letterbox the map. setMinZoom also
// corrects the current zoom if the new minimum exceeds it.
function clampZoomToViewport() {
    map.setMinZoom(Math.max(0, Math.ceil(Math.log2(map.getSize().y / 256))));
}
map.on("resize", clampZoomToViewport);
clampZoomToViewport();

L.tileLayer('https://api.mapbox.com/styles/v1/{id}/tiles/{z}/{x}/{y}@2x?access_token={accessToken}', {
    attribution: '© <a href="https://www.mapbox.com/">Mapbox</a>',
    tileSize: 512,
    zoomOffset: -1,
    id: 'mapbox/dark-v11',
    accessToken: window.MAPBOX_TOKEN || ''
}).addTo(map);

// hq coords (injected by server from HQ_LAT / HQ_LNG env vars)
var hqLatLng = new L.LatLng(window.HQ_LAT_LNG[0], window.HQ_LAT_LNG[1]);

// hq marker
L.circle(hqLatLng, 110000, {
color: 'red',
fillColor: 'yellow',
fillOpacity: 0.5,
}).addTo(map);

// Append <svg> to map
var svg = d3.select(map.getPanes().overlayPane).append("svg")
.attr("class", "leaflet-zoom-animated")
.attr("width", window.innerWidth)
.attr("height", window.innerHeight);

function translateSVG() {
    var viewBoxLeft = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.x;
    var viewBoxTop = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.y;

    // Resizing width and height in case of window resize
    svg.attr("width", window.innerWidth);
    svg.attr("height", window.innerHeight);

    // Adding the ViewBox attribute to our SVG to contain it
    svg.attr("viewBox", function () {
        return "" + viewBoxLeft + " " + viewBoxTop + " "  + window.innerWidth + " " + window.innerHeight;
    });

    // Adding the style attribute to our SVG to translate it
    svg.attr("style", function () {
        return "transform: translate3d(" + viewBoxLeft + "px, " + viewBoxTop + "px, 0px);";
    });
}

function update() {
    translateSVG();
}

// Re-draw on reset, this keeps the markers where they should be on reset/zoom
map.on("moveend", update);

function calcMidpoint(x1, y1, x2, y2, bend) {
    if(y2<y1 && x2<x1) {
        var tmpy = y2;
        var tmpx = x2;
        x2 = x1;
        y2 = y1;
        x1 = tmpx;
        y1 = tmpy;
    }
    else if(y2<y1) {
        y1 = y2 + (y2=y1, 0);
    }
    else if(x2<x1) {
        x1 = x2 + (x2=x1, 0);
    }

    var radian = Math.atan(-((y2-y1)/(x2-x1)));
    var r = Math.sqrt(x2-x1) + Math.sqrt(y2-y1);
    var m1 = (x1+x2)/2;
    var m2 = (y1+y2)/2;

    var min = 2.5, max = 7.5;
    var arcIntensity = parseFloat((Math.random() * (max - min) + min).toFixed(2));

    if (bend === true) {
        var a = Math.floor(m1 - r * arcIntensity * Math.sin(radian));
        var b = Math.floor(m2 - r * arcIntensity * Math.cos(radian));
    } else {
        var a = Math.floor(m1 + r * arcIntensity * Math.sin(radian));
        var b = Math.floor(m2 + r * arcIntensity * Math.cos(radian));
    }

    return {"x":a, "y":b};
}

function translateAlong(path) {
    var l = path.getTotalLength();
    return function(i) {
        return function(t) {
            // Put in try/catch because sometimes floating point is stupid..
            try {
            var p = path.getPointAtLength(t*l);
            return "translate(" + p.x + "," + p.y + ")";
            } catch(err){
            console.log("Caught exception.");
            return "ERROR";
            }
        }
    }
}

function handleParticle(msg, srcPoint) {
    var i = 0;
    var x = srcPoint['x'];
    var y = srcPoint['y'];

    svg.append('circle')
        .attr('cx', x)
        .attr('cy', y)
        .attr('r', 1e-6)
        .style('fill', 'none')
        .style('stroke', msg.color)
        .style('stroke-opacity', 1)
        .transition()
        .duration(2000)
        .ease(Math.sqrt)
        .attr('r', 35)
        .style('stroke-opacity', 1e-6)
        .remove();
}

function handleTraffic(msg, srcPoint, hqPoint) {
    var fromX = srcPoint['x'];
    var fromY = srcPoint['y'];
    var toX = hqPoint['x'];
    var toY = hqPoint['y'];
    var bendArray = [true, false];
    var bend = bendArray[Math.floor(Math.random() * bendArray.length)];

    var lineData = [srcPoint, calcMidpoint(fromX, fromY, toX, toY, bend), hqPoint]
    var lineFunction = d3.svg.line()
        .interpolate("basis")
        .x(function(d) {return d.x;})
        .y(function(d) {return d.y;});

    var lineGraph = svg.append('path')
            .attr('d', lineFunction(lineData))
            .attr('opacity', 0.8)
            .attr('stroke', msg.color)
            .attr('stroke-width', 2)
            .attr('fill', 'none');

    if (translateAlong(lineGraph.node()) === 'ERROR') {
        console.log('translateAlong ERROR')
        return;
    }

    var circleRadius = 6

    // Circle follows the line
    var dot = svg.append('circle')
        .attr('r', circleRadius)
        .attr('fill', msg.color)
        .transition()
        .duration(700)
        .ease('ease-in')
        .attrTween('transform', translateAlong(lineGraph.node()))
        .each('end', function() {
            d3.select(this)
                .transition()
                .duration(500)
                .attr('r', circleRadius * 2.5)
                .style('opacity', 0)
                .remove();
    });

    var length = lineGraph.node().getTotalLength();
    lineGraph.attr('stroke-dasharray', length + ' ' + length)
        .attr('stroke-dashoffset', length)
        .transition()
        .duration(700)
        .ease('ease-in')
        .attr('stroke-dashoffset', 0)
        .each('end', function() {
            d3.select(this)
                .transition()
                .duration(100)
                .style('opacity', 0)
                .remove();
    });
}

var circles = new L.LayerGroup();
map.addLayer(circles);

function addCircle(msg, srcLatLng) {
    circleCount = circles.getLayers().length;
    circleArray = circles.getLayers();

    // Only allow 50 circles to be on the map at a time
    if (circleCount >= 50) {
        circles.removeLayer(circleArray[0]);
    }

    L.circle(srcLatLng, 50000, {
        color: msg.color,
        fillColor: msg.color,
        fillOpacity: 0.2,
        }).addTo(circles);
    }

// WEBSOCKET STUFF

// WebSocket URL is derived from the page's own host so the app works through
// any reverse proxy / IP / port without source edits. Reconnects with a
// capped backoff so the dashboard survives server restarts.
// window.wsState mirrors the latest status because overlay.js (an ES module
// stalled behind CDN imports) can miss CustomEvents dispatched before it loads.
window.wsState = "closed";
(function connectWebSocket(retryDelay) {
    var wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    var webSock = new WebSocket(wsProto + "//" + window.location.host + "/websocket");

    webSock.onopen = function () {
        retryDelay = 1000;
        window.wsState = "open";
        window.dispatchEvent(new CustomEvent("ws-status", { detail: "open" }));
    };

    webSock.onclose = function () {
        window.wsState = "closed";
        window.dispatchEvent(new CustomEvent("ws-status", { detail: "closed" }));
        setTimeout(function () {
            connectWebSocket(Math.min(retryDelay * 2, 15000));
        }, retryDelay);
    };

    webSock.onmessage = function (e) {
        try {
            var msg = JSON.parse(e.data);
            switch (msg.type) {
            case "Traffic":
                var srcLatLng = new L.LatLng(msg.src_lat, msg.src_long);
                var hqPoint = map.latLngToLayerPoint(hqLatLng);
                var srcPoint = map.latLngToLayerPoint(srcLatLng);
                addCircle(msg, srcLatLng);
                handleParticle(msg, srcPoint);
                handleTraffic(msg, srcPoint, hqPoint, srcLatLng);
                window.dispatchEvent(new CustomEvent("attack", { detail: msg }));
                break;
            case "Stats":
                // Mirrored like wsState so overlay.js (stalled behind CDN
                // imports) can seed itself from the latest snapshot at init.
                window.lastStats = msg;
                window.dispatchEvent(new CustomEvent("stats", { detail: msg }));
                break;
            }
        } catch (err) {
            console.log(err);
        }
    };
})(1000);
