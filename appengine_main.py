from google.appengine.ext.webapp.template import render, register_template_library
from google.appengine.ext import ndb
from google.appengine.api import users, memcache
from googleapiclient.errors import HttpError
from urlparse import urlparse
import logging
import webapp2
import config

from third_party import xsrfutil

register_template_library('third_party.xsrfutil')


class Link(ndb.Model):
  url = ndb.StringProperty()
  owner_id = ndb.StringProperty()
  owner_name = ndb.StringProperty()
  viewcount = ndb.IntegerProperty()


def errorPage(response, code, message):
  context = {'code': code, 'message': message, 'corpname': config.CORP_NAME}
  response.write(render('template/error.html', context))
  response.set_status(code)


def check_redirect(func):

  def decorate(self, *args, **kwargs):
    if config.ALWAYS_REDIRECT_TO_FQDN and self.request.host != config.GOLINKS_FQDN:
      url = self.request.url.replace(self.request.host, config.GOLINKS_FQDN, 1)
      return self.redirect(url)
    return func(self, *args, **kwargs)

  return decorate


def isValidUrl(url):
  o = urlparse(url)
  return o.scheme in config.URL_ALLOWED_SCHEMAS


class ShowLinks(webapp2.RequestHandler):

  @check_redirect
  def get(self, param):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url(self.request.path))
      return
    if param == "all":
      links = Link.query().fetch()
    else:
      links = Link.query(Link.owner_id == user.user_id()).fetch()
    context = {
        "links": links,
        "fqdn": config.GOLINKS_FQDN,
        "hostname": config.GOLINKS_HOSTNAME
    }
    self.response.write(render("template/list.html", context))


class DeleteLink(webapp2.RequestHandler):

  @check_redirect
  @xsrfutil.xsrf_protect
  def post(self, link):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url(self.request.path))
      return
    key = link.rstrip("/")
    l = Link.get_by_id(key)
    if l.owner_id:
      if l.owner_id != user.user_id() and not users.is_current_user_admin():
        logging.info("%s tried to delete /%s but doesn't have permission" %
                     (user.email(), key))
        errorPage(self.response, 403, "Access denied")
        return
    l.key.delete()
    logging.info("%s deleted /%s" % (user.email(), key))
    self.redirect("/links/my")


class EditLink(webapp2.RequestHandler):

  @check_redirect
  @xsrfutil.xsrf_protect
  def post(self, link):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url(self.request.path))
      return
    key = self.request.get("key", "").rstrip("/")
    url = self.request.get("url", None)
    if not key:
      errorPage(self.response, 400, "Shortened URL required")
      return
    blacklist = ["edit", "links", "delete"]
    for word in blacklist:
      if key.startswith(word + '/') or key == word:
        logging.info("%s tried to add forbidden URL /%s" % (user.email(), key))
        errorPage(self.response, 400, "Shortened URL forbidden")
        return
    if link:
      if key != link:
        logging.info(
            "%s tried to change /%s to %s but such request is forbidden" %
            (user.email(), link, key))
        errorPage(self.response, 400, "Cannot change shortened URL")
        return
    if not isValidUrl(url):
      logging.info("%s tried to set /%s to illegal URL: %s" %
                   (user.email(), key, url))
      errorPage(self.response, 400, "URL Illegal")
      return
    l = Link.get_or_insert(key)
    if l.owner_id:
      if not link:
        logging.info("%s tried to overwrite /%s" % (user.email(), key))
        errorPage(
            self.response, 500,
            "Link already exists... Please update existing one or change url.")
        return
      if l.owner_id != user.user_id() and not users.is_current_user_admin():
        logging.info("%s tried to modify /%s but doesn't have permission" %
                     (user.email(), key))
        errorPage(self.response, 403, "Access denied")
        return
    else:
      l.owner_id = user.user_id()
      l.owner_name = user.nickname()
    l.url = url
    if not l.viewcount:
      l.viewcount = 0
    l.put()
    logging.info("%s created or updated /%s to %s" % (user.email(), key, url))
    self.redirect("/edit/" + key)

  @check_redirect
  def get(self, link):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url(self.request.path))
      return
    is_admin = users.is_current_user_admin()
    context = {
        'hostname': config.GOLINKS_HOSTNAME
    }
    if link:
      link = link.rstrip("/")
      context.update({'key': link})
      l = Link.get_by_id(link)
      if l:
        if l.owner_id:
          if l.owner_id != user.user_id() and not is_admin:
            logging.info(
                "%s tried to check details page of /%s but doesn't have permission"
                % (user.email(), link))
            errorPage(self.response, 403, "Access denied")
            return
        context.update({
            'url': l.url,
            'viewcount': l.viewcount,
            'can_delete': 1,
            'owner': l.owner_name
        })
    logging.info("%s checked details page of /%s" % (user.email(), link))
    self.response.write(render("template/edit.html", context))


class RedirectLink(webapp2.RequestHandler):

  @check_redirect
  def get(self, link):
    user = users.get_current_user()
    if link:
      link = link.rstrip("/")
      l = Link.get_by_id(link)
      if l:
        if not user:
          self.redirect(users.create_login_url(self.request.path))
          return
        username = user.email()
        l.viewcount += 1
        l.put()
        logging.info("%s accessed /%s and redirected to %s" %
                     (username, link, str(l.url)))
        self.redirect(str(l.url))
        return
    if not user:  # we don't want external to know if url exists
      self.redirect(users.create_login_url(self.request.path))
      return
    if not link:
      self.redirect('/links/my')
      return

    # Link doesn't exist, let's make it!
    self.redirect('/edit/%s' % link.rstrip('/'))


app = webapp2.WSGIApplication([
    ('/edit/([-\/\w]*)', EditLink),
    ('/delete/([-\/\w]+)', DeleteLink),
    ('/links/(\w*)', ShowLinks),
    ('/([-\/\w]*)', RedirectLink),
],
                              debug=True)
