
#include "server.h"

int main()
{
	server s;
	
	s.register_webapi
	(
		webapi_path("/api/shippers/view"), 
		"List of shipping companies",
		http::verb::GET, 
		{} /* inputs */, 	
		{"shippers_access", "sysadmin"},
		[](http::request& req) 
		{
			auto json {sql::get_json_response("DB1", "execute sp_shippers_view")};
			req.response.set_body( json );
		}
	);

	s.register_webapi
	(
		webapi_path("/api/products/view"), 
		"List of products",
		http::verb::GET, 
		{} /* inputs */, 	
		{} /* roles */,
		[](http::request& req) 
		{
			req.response.set_body( sql::get_json_response("DB1", "execute sp_products_view") );
		}
	);

	s.register_webapi
	(
		webapi_path("/api/customer/info"), 
		"Retrieve customer record and the list of his purchase orders",
		http::verb::GET, 
		{{"customerid", http::field_type::STRING, true}}, 	
		{"customer_access", "sysadmin"},
		[](http::request& req)
		{
			auto sql {req.get_sql("execute sp_customer_info $customerid")};
			req.response.set_body(sql::get_json_response("DB1", sql, {"customer", "orders"}));
		}
	);

	s.register_webapi
	(
		webapi_path("/api/sales/query"), 
		"Sales report by category for a period",
		http::verb::GET, 
		{
			{"date1", http::field_type::DATE, true},
			{"date2", http::field_type::DATE, true}
		}, 	
		{"customer_access", "sysadmin"},
		[](http::request& req)
		{
			auto sql {req.get_sql("execute sp_getSalesByCategory $date1, $date2")};
			req.response.set_body(sql::get_json_response("DB1", sql));
		}
	);

	s.start();
}
