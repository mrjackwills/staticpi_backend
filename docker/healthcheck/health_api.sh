#!/bin/sh

# Check the api server /online endpoint
api_check() {
	port=$(grep "API_PORT" /app_env/.api.env | cut -c 10-13)
	url="staticpi_api:${port}/v0/incognito/online"

	# Make the request using curl and process the response
	response=$(curl -s -S --max-time 4 "$url" 2>&1)

	# Extract the uptime value from the JSON response
	uptime=$(echo "$response" | grep -oP '\{.*\}' | grep -oP '"uptime":\K[0-9]+')

	# Check that the uptime is a valid number
	case "$uptime" in
	[0-9]*)
		echo "api_check: 200 OK with valid uptime field: $uptime"
		return
		;;
	*)
		echo "api_check: Error: Uptime field is missing or invalid"
		false
		;;
	esac
}

# Check the token server /online endpoint
token_check() {
	port=$(grep "TOKEN_PORT" /app_env/.api.env | cut -c 12-15)
	url="staticpi_api:${port}/online"

	# Make the request using curl and process the response
	response=$(curl -s -S --max-time 4 "$url" 2>&1)

	# Extract the uptime value from the JSON response
	uptime=$(echo "$response" | grep -oP '\{.*\}' | grep -oP '"uptime":\K[0-9]+')

	# Check that the uptime is a valid number
	case "$uptime" in
	[0-9]*)
		echo "token_check: 200 OK with valid uptime field: $uptime"
		return
		;;
	*)
		echo "token_check: Error: Uptime field is missing or invalid"
		false
		;;
	esac
}

# Check the token server /online endpoint
wss_check() {
	port=$(grep "WS_PORT" /app_env/.api.env | cut -c 9-12)
	url="http://staticpi_api:${port}/online"

	# Make the request using curl and process the response
	response=$(curl -i -N -o - -s -H "Connection: Upgrade" \
		-H "Upgrade: websocket" \
		-H "Sec-WebSocket-Version: 13" \
		-H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
		-H "Host: ${url}" \
		-H "Origin: ${url}" \
		"${url}")

	# Extract the uptime value from the JSON response
	uptime=$(echo "$response" | grep -oP '\{.*\}' | grep -oP '"uptime":\K[0-9]+')

	# Check that the uptime is a valid number
	case "$uptime" in
	[0-9]*)
		echo "wss_check: 200 OK with valid uptime field: $uptime"
		return
		;;
	*)
		echo "wss_check: Error: Uptime field is missing or invalid"
		false
		;;
	esac

}

main() {

	api_check
	api_status=$?
	if [ "$api_status" -gt 0 ]; then
		echo "api_check failed"
		exit $api_status
	fi

	token_check
	token_status=$?
	if [ "$token_status" -gt 0 ]; then
		echo "token_check failed"
		exit $token_status
	fi

	wss_check
	wss_status=$?
	if [ "$wss_status" -gt 0 ]; then
		echo "wss_check failed"
		exit $wss_status
	fi
}

main
