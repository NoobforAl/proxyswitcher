import scrapy


class LabSpider(scrapy.Spider):
    name = "lab"
    start_urls = ["http://target:8080/"]
    custom_settings = {
        "LOG_LEVEL": "WARNING",
        "ROBOTSTXT_OBEY": False,
        "RETRY_ENABLED": False,
        "TELNETCONSOLE_ENABLED": False,
    }

    def parse(self, response):
        print(f"crawled {response.status} {response.url}", flush=True)
        for link in response.css("a::attr(href)").getall():
            yield response.follow(link)
