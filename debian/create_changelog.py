#!/usr/bin/python3
import sys
import re
import textwrap
import datetime
import email.utils

import git

package_name = 'UNKNOWN'

def print_release(tag=None, commits=tuple(), last_tag=None):
	release_version = '0.0.0'
	release_author = git.objects.util.Actor('None', 'undefined@example.com')
	release_date = 0
	release_status = 'UNRELEASED'
	message = ''

	if tag:
		release_status = 'unstable'
		release_version = tag.name[1:] # strip leading "v"
		if isinstance(tag.object, git.TagObject):
			release_author = tag.object.tagger
			release_date = tag.object.tagged_date
			message = tag.object.message.split('-----BEGIN PGP SIGNATURE-----')[0].strip()
		else:
			release_author = tag.object.committer
			release_date = tag.object.committed_date
	elif commits:
		release_author = commits[0].committer
		release_date = commits[0].committed_date
		date = datetime.datetime.fromtimestamp(release_date).strftime('%Y%m%dT%H%M%S')
		last_version = '0.0.0'
		if last_tag:
			last_version = last_tag.name[1:] # strip leading "v"
		release_version = f'{last_version}+git{date}-{commits[0].hexsha[:8]}'

	print(f'{package_name} ({release_version}) {release_status}; urgency=medium')
	print()
	if message:
		print(textwrap.indent(message, '  '))
		print()
	commit_authors = [] # list of (key, author), sorted by first commit date
	commit_author_emails = {} # author email -> key
	commit_author_names = {} # author name -> key
	commit_author_commits = {} # key -> list of commits
	for commit in commits:
		key = commit_author_emails.get(commit.author.email)
		if key is None:
			key = commit_author_names.get(commit.author.name)
		if key is None:
			key = commit.author.email
			commit_authors.append((key, commit.author))
			commit_author_emails[commit.author.email] = key
			commit_author_names[commit.author.name] = key
		commit_author_commits[key] = commit_author_commits.get(key, []) + [commit]
	for key, author in commit_authors:
		print(f'  [ {author.name} ]')
		for commit in commit_author_commits[key]:
			print(f'  * {commit.summary}')
		print()
	print(f' -- {release_author.name} <{release_author.email}>  {email.utils.formatdate(release_date)}')

if __name__ == '__main__':
	repo = git.Repo('.')
	package_name = sys.argv[1]

	version_commits = {}
	for tag in repo.tags:
		if not re.fullmatch('v[0-9]+[.][0-9]+[.][0-9]+.*', tag.name):
			continue
		if isinstance(tag.object, git.TagObject):
			commit_hexsha = tag.object.object.hexsha
		else:
			commit_hexsha = tag.object.hexsha
		version_commits[commit_hexsha] = tag

	tag = None
	commits = []
	for commit in repo.iter_commits('HEAD'):
		if commit.hexsha in version_commits:
			prev_tag = version_commits[commit.hexsha]
			print_release(tag, commits, last_tag=prev_tag)
			print()
			tag = prev_tag
			commits = []
		commits.append(commit)
	print_release(tag, [])
