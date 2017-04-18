/*
 * heatman.js : get a ping result json from a heatman server
 * and display the results.
 */

/*

  probe result format from a probe node.

var probe_example = {
	"probe_name" : "localhost",
	"probe_addr" : "127.0.0.2",
	"updated" : "09:00:10",
	"results" : [ 
{
	"name" : "google",
	"addr" : "8.8.8.8",
	"lossrate" : 10.2,
	"last" : 11,
	"average" : 12,
	"sent" : 128,
	"rtts" : [ 1, 11, 21, 31, 41, 51, 61, 71, 81, 91, 101, -1 ],
},
{
	"name" : "cpu",
	"addr" : "203.178.142.142",
	"lossrate" : 10.2,
	"last" : 11,
	"average" : 12,
	"sent" : 128,
	"rtts" : [ 1, 2, 3, -1, 10, 11, 13, 15, 3 ],
},
{
	"name" : "shonan",
	"addr" : "203.178.142.130",
	"lossrate" : 10.2,
	"last" : 11,
	"average" : 12,
	"sent" : 128,
	"rtts" : [ 1, 2, 3, -1, 10, 11, 13, 15, 3 ],
}
		]

};
*/


function refresh_result(url) {

	$.getJSON(url, function(data){
			probes = data["result"];

			for (var x = 0; x < probes.length; x++) {

				if (!probes[x]) { continue; }

				probe = probes[x];
				delete_probe_result(probe);
				add_probe_result(probe);
			}
		});
}

function delete_probe_result(probe) {
	$("." + probe["probe_name"]).remove();
}

function add_probe_result(probe) {

	var div = $("<div>");

	div.addClass("probe");
	div.addClass(probe["probe_name"])
	div.append($("<h3>")
		   .html("Ping source: " + probe["probe_name"] +
			 " (" + probe["probe_addr"] + "), updated at " +
			 probe["updated"]));

	var table = $("<table>");

	var tr_ref = $("<tr>");
	tr_ref.addClass("reference");
	tr_ref.append($("<td>").html("Name"));
	tr_ref.append($("<td>").html("Address"))
	tr_ref.append($("<td>").html("Sent"));
	tr_ref.append($("<td>").html("Last"));
	tr_ref.append($("<td>").html("Avg"));
	tr_ref.append($("<td>").html("Loss"));
	tr_ref.append($("<td>").html("Result"));

	table.append(tr_ref);

	for (var x = 0; x < probe["results"].length; x++) {
		var tr = result_to_tr(probe["results"][x]);
		table.append(tr);
	}

	div.append(table);

	$("div#body").append(div);
}


function result_to_tr(result)
{
	/* @result: a result of a ping target in a probe result */

	var tr = $("<tr>");

	var td = $("<td>").html(result["name"]);
	td.addClass("target");
	tr.append(td);

	var td = $("<td>").html(result["addr"]);
	td.addClass("target");
	tr.append(td);

	tr.append($("<td>").html(result["sent"]));
	tr.append($("<td>").html(result["last"].toFixed(1)));
	tr.append($("<td>").html(result["average"].toFixed(1)));
	tr.append($("<td>").html(result["lossrate"].toFixed(1) + "%"));

	var graph = "";
	for (var x = 0; x < result["rtts"].length; x++) {
		if (result["rtts"][x] < 0) {
			graph += "<span class='boxfailed";
		} else if (result["rtts"][x] < 5) {
			graph += "<span class='box1";
		} else if (result["rtts"][x] < 10) {
			graph += "<span class='box2";
		} else if (result["rtts"][x] < 20) {
			graph += "<span class='box3";
		} else if (result["rtts"][x] < 50) {
			graph += "<span class='box4";
		} else if (result["rtts"][x] < 80) {
			graph += "<span class='box5";
		} else if (result["rtts"][x] < 100) {
			graph += "<span class='box6";
		} else { /* over 100ms */
			graph += "<span class='boxover";
		}

		if ((x + 1) % 10 == 0) {
			graph += " box-border'>";
		} else {
			graph += "'>";
		}

		graph += "▇</span>";

	}
	tr.append($("<td>").html(graph));

	return tr;
}