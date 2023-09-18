#include "email.h"

namespace smtp
{
	
	mail::mail(const std::string& server, const std::string& user, const std::string& pwd): server_url{server}, username{user}, password{pwd}
	{ }
	
	void mail::build_message() {
		std::string domain;
		if (auto pos = username.find("@"); pos != std::string::npos) 
			domain = username.substr(pos);
				
		body.append("\r\n");
		
		std::vector<std::string> mail_headers {
			std::string("Date: " + http::get_response_date()),
			"To: " + to,
			"From: " + username,
			"Cc: " + cc,
			std::string("Message-ID: <" + http::get_uuid() + domain + ">"),
			"Subject: " + subject
		};

		curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, server_url.c_str());
		if (server_url.ends_with(":587"))
			curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, username.c_str());
		recipients = curl_slist_append(recipients, to.c_str());
		if (!cc.empty())
			recipients = curl_slist_append(recipients, cc.c_str());
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		
		for (const auto& h: mail_headers)
			headers = curl_slist_append(headers, h.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		mime = curl_mime_init(curl);

		part = curl_mime_addpart(mime);
		curl_mime_data(part, body.c_str(), CURL_ZERO_TERMINATED);
		curl_mime_type(part, "text/html");
		
		for (const auto& doc: documents)
		{
			part = curl_mime_addpart(mime);
			curl_mime_encoder(part, doc.encoding.c_str());
			curl_mime_filedata(part, doc.filesystem_path.c_str());
			if (!doc.filename.empty())
				curl_mime_filename(part, doc.filename.c_str());
		}
		
	}
	
	void mail::send() noexcept
	{
		curl = curl_easy_init();
		if (curl) {
			if (debug_mode)
				curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			build_message();
			
			logger::log("email", "info", "sending email to: " + to + " with subject: " + subject, true, x_request_id);
			
			curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
			res = curl_easy_perform(curl);
		 
			if(res != CURLE_OK)
				logger::log("email", "error", "curl_easy_perform() failed: $1", {std::string(curl_easy_strerror(res))}, true, x_request_id);
			
			curl_slist_free_all(recipients);
			curl_slist_free_all(headers);
			curl_easy_cleanup(curl);
			curl_mime_free(mime);
		}
	}

	void mail::add_attachment(const std::string& path, const std::string& filename, const std::string& encoding) noexcept
	{
		attachment doc {path, filename, encoding};
		documents.push_back(doc);
	}

	void mail::add_attachment(const std::string& path) noexcept
	{
		attachment doc {path, "", "base64"};
		documents.push_back(doc);
	}

	void mail::set_to(std::string_view  _to) noexcept
	{
		to = _to;
	}
	
	void mail::set_cc(std::string_view  _cc) noexcept
	{
		cc = _cc;
	}
	
	void mail::set_subject(std::string_view  _subject) noexcept
	{
		subject = _subject;
	}
	
	void mail::set_body(std::string_view  _body) noexcept
	{
		body = _body;
	}
	
	void mail::set_debug(bool _debug) noexcept
	{
		debug_mode = _debug;
	}
	
	void mail::set_x_request_id(std::string_view  _id) noexcept
	{
		x_request_id = _id;
	}
}