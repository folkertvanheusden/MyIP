class private_data
{
public:
	private_data() { }
};

class http_private_data : public private_data
{
public:
	std::string logfile, web_root;
};
