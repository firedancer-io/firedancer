function getLatestRelease(owner, repo) {
  const url = `https://api.github.com/repos/${owner}/${repo}/releases/latest`;

  return fetch(url, {
    headers: {
        Accept: 'application/vnd.github.v3+json'
    }
  }).then(response => {
    if (!response.ok) {
      throw new Error(`Error fetching release: ${response.status} ${response.statusText}`);
    }
    return response.json();
  }).then(data => data.tag_name)
    .catch(error => {
      console.error('Error fetching the latest release:', error);
  });
}

export default function latestVersion() {
  return getLatestRelease('firedancer-io', 'firedancer').then(version => {
    return {
      name: 'version-plugin',
      transform(code, id) {
        if (id.endsWith('.md')) {
          return code.replace(/__FD_LATEST_VERSION__/g, version);
        }
        return code;
      }
    };
  });
}
